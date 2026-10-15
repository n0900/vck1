package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.csc.api.SignHashResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import kotlin.io.encoding.Base64

/** Executes validated CSC operations in order, without retrying completed signatures. */
internal class QesSigningExecutor {

    suspend fun execute(operations: List<QesSigningOperation>): List<QesDocumentSigningResult> =
        operations.map { operation ->
            val response = operation.signHash(operation.request).getOrThrow()
            validateResponse(response)
            QesDocumentSigningResult(
                credentialQueryId = operation.credentialQueryId,
                preparedDocument = operation.preparedDocument,
                request = operation.request,
                response = response,
            )
        }

    private fun validateResponse(response: SignHashResponseParameters) {
        val signature = response.signatures?.singleOrNull()
        val valid = catching {
            require(response.responseId == null && !signature.isNullOrEmpty())
            val decoded = Base64.decode(signature)
            require(decoded.isNotEmpty() && Base64.encode(decoded) == signature)
        }.isSuccess
        if (!valid) throw InvalidRequest("QTSP must return exactly one completed, padded Base64 signature")
    }
}
