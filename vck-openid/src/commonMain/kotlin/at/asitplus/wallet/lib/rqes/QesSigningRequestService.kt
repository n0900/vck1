package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.api.SignHashRequestParameters
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier

/** Local correlation and routing state; only [request] crosses the CSC callback boundary. */
internal data class QesSigningOperation(
    val credentialQueryId: DCQLCredentialQueryIdentifier,
    val preparedDocument: PreparedQesDocument,
    val request: SignHashRequestParameters,
    val signHash: QesQtspSigner,
)

/** Maps validated QES selections to CSC signatures/signHash requests. */
internal class QesSigningRequestService {

    fun create(selections: List<ValidatedQesSigningSelection>): List<QesSigningOperation> =
        selections.map { selection ->
            QesSigningOperation(
                credentialQueryId = selection.credentialQueryId,
                preparedDocument = selection.preparedDocument,
                request = SignHashRequestParameters(
                    credentialId = selection.credential.credentialId,
                    hashes = listOf(selection.preparedDocument.preparation.dtbsr.value.copyOf()),
                    hashAlgorithmOid = selection.preparedDocument.preparation.dtbsr.algorithmOid,
                    signAlgoOid = selection.signingAlgorithm.signAlgo,
                    signAlgoParams = selection.signingAlgorithm.signAlgoParams,
                ),
                signHash = selection.credential.signHash,
            )
        }
}
