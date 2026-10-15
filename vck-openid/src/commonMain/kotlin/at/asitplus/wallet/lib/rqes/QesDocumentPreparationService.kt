package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import at.asitplus.openid.QesRequest
import at.asitplus.openid.TransactionData
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData

/** ETSI TS 119 432 Annex A.7.3 step 2; invoke only after request authentication and validation. */
class QesDocumentPreparationService(
    private val retriever: QesDocumentRetriever?,
    private val preparer: QesDtbsrPreparer?,
) {
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
