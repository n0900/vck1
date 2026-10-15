package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.csc.api.collection_entries.CertificateParameters
import at.asitplus.csc.api.collection_entries.KeyParameters
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.openid.QesRequest
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLX509CredentialQuery
import at.asitplus.openid.dcql.X509MetadataQuery
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.etsi.isValidAt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData

/** A document selection that satisfies the QES signing requirements. */
internal data class ValidatedQesSigningSelection(
    val credentialQueryId: DCQLCredentialQueryIdentifier,
    val preparedDocument: PreparedQesDocument,
    val credential: QesSigningCredential,
    val signingAlgorithm: SigningAlgorithm,
)

/** Checks eligibility of the complete QES signing selection. */
internal class QesSigningValidator {

    fun validate(
        query: DCQLQuery,
        transactions: List<TransactionData>,
        documents: List<PreparedQesDocument>,
        credentials: Map<DCQLCredentialQueryIdentifier, QesSigningCredential>,
        choices: List<QesDocumentSigningChoice>,
    ): List<ValidatedQesSigningSelection> = catching {
        validateSigningCredentials(query, credentials)

        val selections = resolveDocumentChoices(transactions, documents, choices)
        validateTransactionCredentials(choices, credentials.keys)
        selections.map { (document, choice) ->
            validateDocumentChoice(
                transaction = transactions[document.transactionIndex] as QesRequest,
                document = document,
                credential = credentials.getValue(choice.credentialQueryId),
                choice = choice,
            )
        }
    }.getOrElse {
        if (it is InvalidRequest || it is InvalidTransactionData) throw it
        else throw InvalidTransactionData("Invalid QES signing selection", it)
    }

    private fun validateSigningCredentials(
        query: DCQLQuery,
        credentials: Map<DCQLCredentialQueryIdentifier, QesSigningCredential>,
    ) {
        credentials.forEach { (id, credential) ->
            val credentialQuery = query.credentials.firstOrNull { it.id == id } as? DCQLX509CredentialQuery
                ?: throw InvalidTransactionData("Signing selection must reference an X.509 query")
            validateCredential(credentialQuery, credential)
        }
    }

    private fun resolveDocumentChoices(
        transactions: List<TransactionData>,
        documents: List<PreparedQesDocument>,
        choices: List<QesDocumentSigningChoice>,
    ): List<Pair<PreparedQesDocument, QesDocumentSigningChoice>> {
        val expected = transactions.flatMapIndexed { transactionIndex, transaction ->
            (transaction as? QesRequest)?.signatureRequests.orEmpty().indices.map { transactionIndex to it }
        }
        require(expected.isNotEmpty()) { "QES requires signature requests" }
        val prepared = documents.associateBy { it.transactionIndex to it.signatureRequestIndex }
        val selected = choices.associateBy { it.transactionIndex to it.signatureRequestIndex }
        require(prepared.size == documents.size && prepared.keys == expected.toSet()) {
            "Prepared QES documents do not cover the original signature requests"
        }
        require(selected.size == choices.size && selected.keys == expected.toSet()) {
            "QES signing choices must cover each prepared document exactly once"
        }
        return expected.map { prepared.getValue(it) to selected.getValue(it) }
    }

    private fun validateTransactionCredentials(
        choices: List<QesDocumentSigningChoice>,
        credentialQueryIds: Set<DCQLCredentialQueryIdentifier>,
    ) {
        // One authorizing credential per transaction, even when credential_ids offers alternatives.
        choices.groupBy { it.transactionIndex }.values.forEach { transactionChoices ->
            require(transactionChoices.map { it.credentialQueryId }.distinct().size == 1) {
                "A QES transaction must use one selected signing credential"
            }
        }
        require(credentialQueryIds == choices.map { it.credentialQueryId }.toSet()) {
            "Every selected signing credential must authorize a document"
        }
    }

    private fun validateDocumentChoice(
        transaction: QesRequest,
        document: PreparedQesDocument,
        credential: QesSigningCredential,
        choice: QesDocumentSigningChoice,
    ): ValidatedQesSigningSelection {
        val request = transaction.signatureRequests[choice.signatureRequestIndex]
        require(choice.credentialQueryId.string in transaction.credentialIds) {
            "Signing choice is outside the transaction's credential_ids"
        }
        require(
            credential.credentialInfo.signatureQualifier == request.signatureQualifier &&
                    (transaction.signatureQualifier == null || transaction.signatureQualifier == request.signatureQualifier)
        ) {
            "Signing credential cannot produce the requested signature qualifier"
        }
        val algorithm = resolveSigningAlgorithm(request, choice, credential)
        validateAlgorithmCompatibility(algorithm, document, credential)
        return ValidatedQesSigningSelection(
            credentialQueryId = choice.credentialQueryId,
            preparedDocument = document,
            credential = credential,
            signingAlgorithm = algorithm,
        )
    }

    private fun resolveSigningAlgorithm(
        request: QesSignatureRequest,
        choice: QesDocumentSigningChoice,
        credential: QesSigningCredential,
    ): SigningAlgorithm {
        val algorithm = choice.signingAlgorithm ?: request.signingAlgorithm
        ?: throw InvalidTransactionData("QES requires an explicit signing algorithm choice")
        require(request.signingAlgorithm == null || algorithm == request.signingAlgorithm) {
            "Signing algorithm differs from the original request"
        }
        require(algorithm.signAlgo in credential.credentialInfo.keyParameters.algo) {
            "Signing algorithm is not supported by the credential"
        }
        return algorithm
    }

    private fun validateAlgorithmCompatibility(
        algorithm: SigningAlgorithm,
        document: PreparedQesDocument,
        credential: QesSigningCredential,
    ) {
        val resolvedAlgorithm = algorithm.toSignatureAlgorithmOrNull()
            ?: throw InvalidTransactionData("Unsupported QES signing algorithm or parameters")
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
    }

    private fun validateCredential(query: DCQLX509CredentialQuery, credential: QesSigningCredential) {
        require(query.claims == null && query.claimSets == null && query.trustedAuthorities == null) {
            "Additional X.509 claims or trusted-authority constraints are not supported"
        }
        val certificate = validateCredentialStatus(credential)
        val key = certificate.decodedPublicKey.getOrThrow()
        val parameters = credential.credentialInfo.keyParameters
        validateProviderKeyMetadata(key, parameters)
        validateCertificateMetadata(query.meta, certificate)
        validateKeyConfigurations(query.meta, key, parameters)
    }

    private fun validateCredentialStatus(credential: QesSigningCredential): X509Certificate {
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
        return certificate
    }

    private fun validateProviderKeyMetadata(key: CryptoPublicKey, parameters: KeyParameters) {
        require(
            when (key) {
                is CryptoPublicKey.EC -> parameters.curve == key.curve.oid
                is CryptoPublicKey.RSA -> parameters.curve == null && parameters.len == key.bits.number
            }
        ) { "Provider key metadata does not match the certificate" }
    }

    private fun validateCertificateMetadata(meta: X509MetadataQuery, certificate: X509Certificate) {
        with(meta) {
            certificateFingerprints?.let { fingerprints ->
                fingerprints.forEach { require(it.digest.outputLength.bits >= 256U) { "Weak certificate fingerprint" } }
                require(fingerprints.any { it.value.contentEquals(it.digest.digest(certificate.encodeToDer())) }) {
                    "Certificate fingerprint does not match"
                }
            }
            if (certificatePolicies.isNotEmpty()) require(certificate.policyOids().any { it in certificatePolicies }) {
                "Certificate policy does not match"
            }
        }
    }

    private fun validateKeyConfigurations(meta: X509MetadataQuery, key: CryptoPublicKey, parameters: KeyParameters) {
        meta.keys?.let { configurations ->
            require(configurations.any { configuration ->
                (configuration.algo == key.oid.toString() ||
                        parameters.algo.any { it.toString() == configuration.algo }) && when (key) {
                    is CryptoPublicKey.EC -> configuration.len == null && configuration.curve == key.curve.oid.toString()
                    is CryptoPublicKey.RSA -> configuration.curve == null && configuration.len?.toUInt() == key.bits.number
                }
            }) { "Signing key configuration does not match" }
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
