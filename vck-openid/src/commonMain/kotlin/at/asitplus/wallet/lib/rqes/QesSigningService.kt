package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.csc.api.SignHashRequestParameters
import at.asitplus.csc.api.SignHashResponseParameters
import at.asitplus.csc.api.collection_entries.CertificateParameters
import at.asitplus.csc.api.collection_entries.KeyParameters
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.QesRequest
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLCredentialSetQuery
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLX509CredentialQuery
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.etsi.isValidAt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import kotlin.io.encoding.Base64

/** Local correlation and routing state; only [request] crosses the CSC callback boundary. */
internal data class QesSigningOperation(
    val credentialQueryId: DCQLCredentialQueryIdentifier,
    val preparedDocument: PreparedQesDocument,
    val request: SignHashRequestParameters,
    val signHash: QesQtspSigner,
)

/** Validates the whole operation before any signing side effects. State must come from request preparation. */
internal class QesSigningService {
    suspend fun validate(
        state: AuthorizationResponsePreparationState,
        submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<StoreEntry>>>,
        credentials: Map<DCQLCredentialQueryIdentifier, QesSigningCredential>,
        choices: List<QesDocumentSigningChoice>,
    ): List<QesSigningOperation> = catching {
        val query = state.request.parameters.dcqlQuery ?: throw InvalidRequest("QES requires DCQL")
        require(state.credentialPresentationRequest == CredentialPresentationRequest.DCQLRequest(query)) {
            "QES preparation does not match the authorization request"
        }
        val selectedIds = submissions.keys + credentials.keys
        require(selectedIds.all { id -> query.credentials.any { it.id == id } }) { "Unknown selected DCQL query" }
        query.checkCredentialSetQueryRequirements(selectedIds).getOrThrow()
        require(submissions.values.all { it.isNotEmpty() }) { "Empty ordinary credential submission" }
        submissions.forEach { (id, selected) ->
            val credentialQuery = query.credentials.first { it.id == id }
            require(credentialQuery !is DCQLX509CredentialQuery) { "X.509 requires a signing credential" }
            require(credentialQuery.multiple || selected.size == 1) { "Multiple submissions are not permitted" }
        }
        credentials.forEach { (id, credential) ->
            val credentialQuery = query.credentials.first { it.id == id } as? DCQLX509CredentialQuery
                ?: throw InvalidTransactionData("Signing selection must reference an X.509 query")
            validateCredential(credentialQuery, credential)
        }

        // Match explicit ordinary submissions again, so caller-supplied matching results cannot bypass DCQL.
        ordinaryPresentation(query, submissions)?.let { presentation ->
            val selected = submissions.values.flatten().map { it.credential }.distinct()
            val matches = DCQLQueryAdapter(presentation.presentationRequest.dcqlQuery).select(selected)
            submissions.forEach { (id, options) ->
                options.forEach { option ->
                    require(matches.credentialQueryMatches[id].orEmpty().any { (index, matching) ->
                        selected[index.toInt()] == option.credential && matching == option.matchingResult
                    }) { "Ordinary submission does not match DCQL query ${id.string}" }
                }
            }
        }

        val transactions = state.request.parameters.transactionDataDecoded.orEmpty()
        val expected = transactions.flatMapIndexed { transactionIndex, transaction ->
            (transaction as? QesRequest)?.signatureRequests.orEmpty().indices.map { transactionIndex to it }
        }
        require(expected.isNotEmpty()) { "QES requires signature requests" }
        val prepared = state.preparedQesDocuments.associateBy { it.transactionIndex to it.signatureRequestIndex }
        val selected = choices.associateBy { it.transactionIndex to it.signatureRequestIndex }
        require(prepared.size == state.preparedQesDocuments.size && prepared.keys == expected.toSet()) {
            "Prepared QES documents do not cover the original signature requests"
        }
        require(selected.size == choices.size && selected.keys == expected.toSet()) {
            "QES signing choices must cover each prepared document exactly once"
        }
        // One authorizing credential per transaction, even when credential_ids offers alternatives.
        choices.groupBy { it.transactionIndex }.values.forEach { transactionChoices ->
            require(transactionChoices.map { it.credentialQueryId }.distinct().size == 1) {
                "A QES transaction must use one selected signing credential"
            }
        }
        require(credentials.keys == choices.map { it.credentialQueryId }.toSet()) {
            "Every selected signing credential must authorize a document"
        }
        expected.map { index ->
            val transaction = transactions[index.first] as QesRequest
            val request = transaction.signatureRequests[index.second]
            val choice = selected.getValue(index)
            require(choice.credentialQueryId.string in transaction.credentialIds) {
                "Signing choice is outside the transaction's credential_ids"
            }
            val credential = credentials.getValue(choice.credentialQueryId)
            require(
                credential.credentialInfo.signatureQualifier == request.signatureQualifier &&
                        (transaction.signatureQualifier == null || transaction.signatureQualifier == request.signatureQualifier)
            ) {
                "Signing credential cannot produce the requested signature qualifier"
            }
            val algorithm = choice.signingAlgorithm ?: request.signingAlgorithm
            ?: throw InvalidTransactionData("QES requires an explicit signing algorithm choice")
            require(request.signingAlgorithm == null || algorithm == request.signingAlgorithm) {
                "Signing algorithm differs from the original request"
            }
            require(algorithm.signAlgo in credential.credentialInfo.keyParameters.algo) {
                "Signing algorithm is not supported by the credential"
            }
            val resolvedAlgorithm = algorithm.toSignatureAlgorithmOrNull()
                ?: throw InvalidTransactionData("Unsupported QES signing algorithm or parameters")
            val document = prepared.getValue(index)
            val dtbsr = document.preparation.dtbsr
            val digest = when (resolvedAlgorithm) {
                is SignatureAlgorithm.ECDSA -> resolvedAlgorithm.digest
                is SignatureAlgorithm.RSA -> resolvedAlgorithm.digest
            }
            require(digest == dtbsr.digest && dtbsr.value.size.toUInt() * 8U == dtbsr.digest.outputLength.bits) {
                "Signing algorithm and prepared DTBSR digest are incompatible"
            }
            val key = credential.credentialInfo.certParameters!!.certificates!!.first().decodedPublicKey.getOrThrow()
            require(
                when (resolvedAlgorithm) {
                    is SignatureAlgorithm.ECDSA -> key is CryptoPublicKey.EC &&
                            (resolvedAlgorithm.requiredCurve == null || resolvedAlgorithm.requiredCurve == key.curve)

                    is SignatureAlgorithm.RSA -> key is CryptoPublicKey.RSA
                }
            ) { "Signing algorithm is incompatible with the certificate key" }
            QesSigningOperation(
                credentialQueryId = choice.credentialQueryId,
                preparedDocument = document,
                request = SignHashRequestParameters(
                    credentialId = credential.credentialId,
                    hashes = listOf(dtbsr.value.copyOf()),
                    hashAlgorithmOid = dtbsr.algorithmOid,
                    signAlgoOid = algorithm.signAlgo,
                    signAlgoParams = algorithm.signAlgoParams,
                ),
                signHash = credential.signHash,
            )
        }
    }.getOrElse {
        if (it is InvalidRequest || it is InvalidTransactionData) throw it
        else throw InvalidTransactionData("Invalid QES signing selection", it)
    }

    /** Validate the full query first; this projection only creates the ordinary credential artifacts. */
    fun ordinaryPresentation(
        query: DCQLQuery,
        submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<StoreEntry>>>,
    ): CredentialPresentation.DCQLPresentation? {
        val ordinary = query.credentials.filter { it !is DCQLX509CredentialQuery }
        if (ordinary.isEmpty()) return null
        return CredentialPresentation.DCQLPresentation(
            presentationRequest = CredentialPresentationRequest.DCQLRequest(
                DCQLQuery(
                    credentials = DCQLCredentialQueryList(ordinary.toNonEmptyList()),
                    credentialSets = listOf(
                        DCQLCredentialSetQuery(
                            // The original requirements were checked against the complete selection above.
                            options = listOf(ordinary.map { it.id }).toNonEmptyList(),
                            required = false,
                        )
                    ).toNonEmptyList(),
                )
            ),
            credentialQuerySubmissions = submissions,
        )
    }

    fun validateResponse(response: SignHashResponseParameters) {
        val signature = response.signatures?.singleOrNull()
        val valid = catching {
            require(response.responseId == null && !signature.isNullOrEmpty())
            val decoded = Base64.decode(signature)
            require(decoded.isNotEmpty() && Base64.encode(decoded) == signature)
        }.isSuccess
        if (!valid) throw InvalidRequest("QTSP must return exactly one completed, padded Base64 signature")
    }

    private fun validateCredential(query: DCQLX509CredentialQuery, credential: QesSigningCredential) {
        require(query.claims == null && query.claimSets == null && query.trustedAuthorities == null) {
            "Additional X.509 claims or trusted-authority constraints are not supported"
        }
        require(credential.credentialId.isNotBlank()) { "Missing signing credential ID" }
        val info = credential.credentialInfo
        require(info.credentialID == null || info.credentialID == credential.credentialId) { "Credential ID mismatch" }
        require(info.keyParameters.status == KeyParameters.KeyStatusOptions.ENABLED) { "Signing key is disabled" }
        val certificateStatus = info.certParameters?.status
        require(certificateStatus == null || certificateStatus == CertificateParameters.CertStatus.VALID) {
            "Signing certificate status is not valid"
        }
        val certificate = info.certParameters?.certificates?.firstOrNull()
            ?: throw InvalidTransactionData("Signing credential requires its certificate")
        require(certificate.isValidAt()) { "Signing certificate is outside its validity period" }
        val key = certificate.decodedPublicKey.getOrThrow()
        require(
            when (key) {
                is CryptoPublicKey.EC -> info.keyParameters.curve == key.curve.oid
                is CryptoPublicKey.RSA -> info.keyParameters.curve == null && info.keyParameters.len == key.bits.number
            }
        ) { "Provider key metadata does not match the certificate" }
        with(query.meta) {
            certificateFingerprints?.let { fingerprints ->
                fingerprints.forEach { require(it.digest.outputLength.bits >= 256U) { "Weak certificate fingerprint" } }
                require(fingerprints.any { it.value.contentEquals(it.digest.digest(certificate.encodeToDer())) }) {
                    "Certificate fingerprint does not match"
                }
            }
            if (certificatePolicies.isNotEmpty()) require(certificate.policyOids().any { it in certificatePolicies }) {
                "Certificate policy does not match"
            }
            keys?.let { configurations ->
                require(configurations.any { configuration ->
                    (configuration.algo == key.oid.toString() ||
                            info.keyParameters.algo.any { it.toString() == configuration.algo }) && when (key) {
                        is CryptoPublicKey.EC -> configuration.len == null && configuration.curve == key.curve.oid.toString()
                        is CryptoPublicKey.RSA -> configuration.curve == null && configuration.len?.toUInt() == key.bits.number
                    }
                }) { "Signing key configuration does not match" }
            }
        }
    }

    private fun X509Certificate.policyOids(): List<String> {
        val extensions = tbsCertificate.extensions.orEmpty().filter { it.oid == ObjectIdentifier("2.5.29.32") }
        if (extensions.isEmpty()) return emptyList()
        require(extensions.size == 1) { "Duplicate certificate policies extension" }
        return Asn1Element.parse(extensions.single().value.asOctetString().content).asSequence().children.map {
            it.asSequence().children.first().asPrimitive().readOid().toString()
        }
    }
}
