package at.asitplus.wallet.lib.rqes

import at.asitplus.KmmResult
import at.asitplus.csc.api.SignHashRequestParameters
import at.asitplus.csc.api.SignHashResponseParameters

/**
 * Application-supplied CSC signatures/signHash interaction. VC-K provides no QTSP implementation.
 * Implementations own provider authorization (including SAD), authentication and transport, and must preserve the
 * supplied hashes and signing parameters. Credential selection and provider policy belong to the application.
 */
fun interface QesQtspSigner {
    suspend operator fun invoke(request: SignHashRequestParameters): KmmResult<SignHashResponseParameters>
}
