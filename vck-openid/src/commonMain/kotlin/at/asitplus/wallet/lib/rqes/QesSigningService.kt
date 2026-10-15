package at.asitplus.wallet.lib.rqes

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.wallet.lib.agent.PresentationResponseParameters.DCQLParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.PresentationFactory

/** Coordinates QES signing after application consent. */
class QesSigningService(
    private val openId4VpHolder: OpenId4VpHolder,
) {
    private val qesSigningValidator = QesSigningValidator()
    private val qesSigningRequestService = QesSigningRequestService()
    private val qesSigningExecutor = QesSigningExecutor()

    /**
     * ETSI TS 119 432 Annex A.7.3 step 4. Invoke only after the app obtains explicit consent, using the unmodified
     * [preparationState] returned by [OpenId4VpHolder.startAuthorizationResponsePreparation]. Selections must be explicit;
     * an empty [credentialSubmissions] map is appropriate for an X.509-only request.
     *
     * Validates the complete DCQL selection, creates ordinary presentations, then signs each prepared document in
     * request order. Does not retry: on failure, earlier remote signing operations may already have completed.
     * Returns raw CSC signatures; container construction, embedding and response delivery (steps 5–6) are separate.
     * Each selected credential's [QesSigningCredential.signHash] callback uses the CSC signatures/signHash contract;
     * the application supplies its provider authorization and transport.
     */
    suspend fun execute(
        preparationState: AuthorizationResponsePreparationState,
        credentialSubmissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>,
        signingCredentials: Map<DCQLCredentialQueryIdentifier, QesSigningCredential>,
        signingChoices: List<QesDocumentSigningChoice>,
    ): KmmResult<QesSigningResult> = catching {
        val ordinaryPresentation = PresentationFactory.prepareQesCredentialPresentation(
            preparationState, credentialSubmissions, signingCredentials.keys,
        )
        val selections = qesSigningValidator.validate(
            query = preparationState.request.parameters.dcqlQuery ?: throw InvalidRequest("QES requires DCQL"),
            transactions = preparationState.request.parameters.transactionDataDecoded.orEmpty(),
            documents = preparationState.preparedQesDocuments.orEmpty(),
            credentials = signingCredentials,
            choices = signingChoices,
        )
        val operations = qesSigningRequestService.create(selections)
        val presentations = ordinaryPresentation?.let {
            openId4VpHolder.createPresentation(preparationState, it).getOrElse { error ->
                if (error is OAuth2Exception.AccessDenied && error.cause is IllegalArgumentException)
                    throw InvalidTransactionData("Invalid QES credential submission", error.cause)
                throw error
            } as DCQLParameters
        } ?: DCQLParameters(emptyMap())
        val results = qesSigningExecutor.execute(operations)
        QesSigningResult(presentations, results)
    }
}
