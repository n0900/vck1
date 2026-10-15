package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.QesRequest
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLCredentialSetQuery
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLX509CredentialQuery
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState

/** ETSI TS 119 432 Annex A.7.3 step 2; invoke only after request authentication and validation. */
class QesDocumentPreparationService(
    private val retriever: QesDocumentRetriever?,
    private val preparer: QesDtbsrPreparer?,
) {
    /** Check the combined selection, then let Holder validate and present the ordinary credentials. */
    internal fun prepareQesCredentialPresentation(
        state: AuthorizationResponsePreparationState,
        submissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>,
        signingQueryIds: Set<DCQLCredentialQueryIdentifier>,
    ): CredentialPresentation.DCQLPresentation? {
        val query = state.request.parameters.dcqlQuery ?: throw InvalidRequest("QES requires DCQL")
        if (state.credentialPresentationRequest != CredentialPresentationRequest.DCQLRequest(query))
            throw InvalidTransactionData("QES preparation does not match the authorization request")
        val selectedIds = submissions.keys + signingQueryIds
        if (selectedIds.any { id -> query.credentials.none { it.id == id } })
            throw InvalidTransactionData("Unknown selected DCQL query")
        query.checkCredentialSetQueryRequirements(selectedIds).getOrElse {
            throw InvalidTransactionData("QES selection does not satisfy DCQL credential sets", it)
        }
        val ordinary = query.credentials.filter { it !is DCQLX509CredentialQuery }
        if (submissions.keys.any { id -> ordinary.none { it.id == id } })
            throw InvalidTransactionData("X.509 requires a signing credential")
        if (ordinary.isEmpty()) return null
        return CredentialPresentation.DCQLPresentation(
            presentationRequest = CredentialPresentationRequest.DCQLRequest(
                query.copy(
                    credentials = DCQLCredentialQueryList(ordinary.toNonEmptyList()),
                    // The original sets were satisfied by the combined ordinary and signing selection above.
                    credentialSets = nonEmptyListOf(
                        DCQLCredentialSetQuery(
                            options = nonEmptyListOf(ordinary.map { it.id }), required = false,
                        )
                    ),
                )
            ),
            credentialQuerySubmissions = submissions,
        )
    }

    suspend fun prepare(transactions: List<TransactionData>): List<PreparedQesDocument> = buildList {
        transactions.forEachIndexed { transactionIndex, transaction ->
            if (transaction is QesRequest) addAll(prepareTransaction(transaction, transactionIndex))
        }
    }

    private suspend fun prepareTransaction(transaction: QesRequest, transactionIndex: Int): List<PreparedQesDocument> {
        val prepare = preparer ?: throw InvalidRequest("QES requires a DTBSR preparer")
        return transaction.signatureRequests.mapIndexed { signatureRequestIndex, request ->
            val document = resolveDocument(request.document)
            PreparedQesDocument(
                transactionIndex = transactionIndex,
                signatureRequestIndex = signatureRequestIndex,
                document = document,
                integrityVerified = (request.document as? DocumentReference)?.checksum != null,
                preparation = prepareDtbsr(request, document, prepare),
            )
        }
    }

    private suspend fun resolveDocument(source: SignatureRequestContent): ByteArray = when (source) {
        is DocumentData -> source.document.copyOf()
        is DocumentReference -> retrieveDocument(source).also { verifyChecksum(source, it) }
    }

    private suspend fun retrieveDocument(reference: DocumentReference): ByteArray {
        val retrieve = retriever ?: throw InvalidRequest("QES document reference requires a retriever")
        return catching { retrieve(reference).getOrThrow().copyOf() }
            .getOrElse { throw InvalidRequest("QES document retrieval failed", it) }
    }

    private fun verifyChecksum(reference: DocumentReference, document: ByteArray) {
        val checksum = reference.checksum ?: return
        if (checksum.digest.outputLength.bits < 256U)
            throw InvalidTransactionData("QES document checksum requires SHA-256 or stronger")
        if (!checksum.value.contentEquals(checksum.digest.digest(document)))
            throw InvalidTransactionData("QES document checksum mismatch")
    }

    private suspend fun prepareDtbsr(
        request: QesSignatureRequest,
        document: ByteArray,
        prepare: QesDtbsrPreparer,
    ): QesDocumentPreparation {
        val preparation = catching { prepare(request, document.copyOf()).getOrThrow() }
            .getOrElse { throw InvalidRequest("QES DTBSR preparation failed", it) }
        if (preparation.dtbsr.value.size.toUInt() * 8U != preparation.dtbsr.digest.outputLength.bits)
            throw InvalidTransactionData("QES DTBSR length does not match its digest algorithm")
        return preparation
    }
}
