package at.asitplus.wallet.lib.rqes

import at.asitplus.KmmResult
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads

/**
 * Retrieves the exact document bytes, including access-controlled resources and data URLs.
 * Implementations own HTTP, authentication, redirects, and resource-size/media-type restrictions.
 * The wallet verifies [DocumentReference.checksum] after retrieval.
 */
typealias QesDocumentRetriever = suspend (DocumentReference) -> KmmResult<ByteArray>

/**
 * Prepares a format-specific DTBSR from resolved document bytes and the complete signing request.
 * Implementations own format handling (e.g. PAdES ByteRange), algorithm selection consistent with the request,
 * and preparation context for later signature embedding. The input bytes may be modified by the implementation.
 */
typealias QesDtbsrPreparer = suspend (QesSignatureRequest, ByteArray) -> KmmResult<QesDocumentPreparation>

/** Result of external document preparation; this is wallet state, not a CSC wire object. */
@Serializable
data class QesDocumentPreparation @JvmOverloads constructor(
    /** Hash to authorize and sign, distinct from the source document's integrity checksum. */
    val dtbsr: Hash,
    /** Opaque, service-defined state, including prepared document bytes when needed for later embedding. */
    @Serializable(with = ByteArrayBase64Serializer::class)
    val context: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean = this === other || other is QesDocumentPreparation &&
            dtbsr == other.dtbsr && context.contentEquals(other.context)

    override fun hashCode(): Int = 31 * dtbsr.hashCode() + (context?.contentHashCode() ?: 0)
}

/** A prepared document associated with its unchanged, signed transaction and signature request. */
@Serializable
data class PreparedQesDocument(
    /** Index in the original authorization request's transaction_data, including non-QES transactions. */
    val transactionIndex: Int,
    /** Index in that QES transaction's signatureRequests. */
    val signatureRequestIndex: Int,
    /** Original resolved bytes, before any format-specific preparation. */
    @Serializable(with = ByteArrayBase64Serializer::class)
    val document: ByteArray,
    /** True only when a supplied document-reference checksum was successfully verified. */
    val integrityVerified: Boolean,
    val preparation: QesDocumentPreparation,
) {
    override fun equals(other: Any?): Boolean = this === other || other is PreparedQesDocument &&
            transactionIndex == other.transactionIndex && signatureRequestIndex == other.signatureRequestIndex &&
            document.contentEquals(other.document) && integrityVerified == other.integrityVerified &&
            preparation == other.preparation

    override fun hashCode(): Int {
        var result = transactionIndex
        result = 31 * result + signatureRequestIndex
        result = 31 * result + document.contentHashCode()
        result = 31 * result + integrityVerified.hashCode()
        return 31 * result + preparation.hashCode()
    }
}
