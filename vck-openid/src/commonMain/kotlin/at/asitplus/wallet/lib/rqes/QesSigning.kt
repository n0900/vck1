package at.asitplus.wallet.lib.rqes

import at.asitplus.KmmResult
import at.asitplus.csc.api.CredentialInfo
import at.asitplus.csc.api.SignHashRequestParameters
import at.asitplus.csc.api.SignHashResponseParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import kotlin.jvm.JvmOverloads

/**
 * Executes CSC API signatures/signHash using its standard request and response models.
 * The application supplies authorization and transport for the selected credential. It may add SAD with
 * [SignHashRequestParameters.copy] or use a credential-scoped access token in the HTTP Authorization header.
 * Preserve the supplied hashes and algorithm parameters. Return the synchronous response with one Base64 signature.
 * AdES format/conformance handling belongs to document preparation and subsequent signature construction.
 */
typealias QesQtspSigner = suspend (SignHashRequestParameters) -> KmmResult<SignHashResponseParameters>

/**
 * Metadata and a CSC signHash callback from the application's trusted provider integration.
 * Bind [signHash] to this credential's QTSP and authorization context; credential IDs are provider-local.
 * The library checks metadata and validity, not provider trust or revocation.
 */
data class QesSigningCredential(
    val credentialId: String,
    val credentialInfo: CredentialInfo,
    val signHash: QesQtspSigner,
)

/** One explicit post-consent choice for a document prepared in Annex A.7.3 step 2. */
data class QesDocumentSigningChoice @JvmOverloads constructor(
    val transactionIndex: Int,
    val signatureRequestIndex: Int,
    val credentialQueryId: DCQLCredentialQueryIdentifier,
    /** Required when the original signature request does not specify an algorithm. */
    val signingAlgorithm: SigningAlgorithm? = null,
)

/** Raw CSC signature correlated with its document and the context needed for subsequent container/embedding work. */
data class QesDocumentSigningResult(
    val credentialQueryId: DCQLCredentialQueryIdentifier,
    val preparedDocument: PreparedQesDocument,
    /** Request prepared by VC-K, before application-supplied authorization. */
    val request: SignHashRequestParameters,
    val response: SignHashResponseParameters,
)

/** Annex A.7.3 step 4 artifacts; this is not yet an OpenID4VP authorization response. */
data class QesSigningResult(
    val credentialPresentations: PresentationResponseParameters.DCQLParameters,
    val signingResults: List<QesDocumentSigningResult>,
)
