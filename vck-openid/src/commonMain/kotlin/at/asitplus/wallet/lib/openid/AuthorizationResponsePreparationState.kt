package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.rqes.PreparedQesDocument
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads

/**
 * Intermediate result class to display information about the authentication process to the user,
 * i.e., to let them make an informed decision.
 */
@Serializable
data class AuthorizationResponsePreparationState @JvmOverloads constructor(
    val request: RequestParametersFrom<AuthenticationRequestParameters>,
    /** Extracted from [request], probably fetched remotely. */
    val credentialPresentationRequest: CredentialPresentationRequest?,
    /** Extracted from [request], probably fetched remotely. */
    val clientMetadata: RelyingPartyMetadata?,
    /** Extracted from [request], probably fetched remotely. */
    val jsonWebKeys: Collection<JsonWebKey>?,
    val verifierInfo: NonEmptyList<VerifierInfo>?,
    /** Audience of the presentation to create */
    val audience: String,
    /** QES documents prepared for consent and signing, associated with the original signed request by index. */
    val preparedQesDocuments: List<PreparedQesDocument> = emptyList(),
) {
    val dcApiCallingOrigin: String?
        get() = (request as? RequestParametersFrom.DcApiRequest)?.callingOrigin

    val responseRequiresEncryption: Boolean
        get() = request.parameters.responseMode?.requiresEncryption == true

    /** Whether the authn request arrived encrypted for a key from `wallet_metadata`, see OpenID4VP 1.0, 5.10. */
    val requestWasEncrypted: Boolean
        get() = request.decryptedFrom != null

}
