package at.asitplus.wallet.lib.openid

import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QesRequest
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.encodeToParameters
import at.asitplus.openid.toBase64UrlJsonString
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.utils.DefaultMapStore
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonPrimitive

val OpenId4VpQesRequestTest by matrixSuite {
    listOf("direct", "request", "request_uri", "request_uri_post")
        .asData(nameFn = { "resolves a trusted QES JAR via $it" }) test { transport ->
        val fixture = QesPreparationFixture()
        // Keep a non-canonical JSON encoding to prove the original transaction bytes survive verification.
        val transaction = (" \n" + joseCompliantSerializer.encodeToString(TransactionData.serializer(), fixture.transaction))
            .encodeToByteArray().encodeToString(Base64UrlStrict)
        val parameters = fixture.parameters.copy(transactionData = listOf(JsonPrimitive(transaction)))
        val jar = fixture.sign(parameters)
        var fetched: RemoteResourceRetrieverInput? = null
        var expectedParameters = parameters
        var returnedJar = jar
        val holder = OpenId4VpHolder(
            relyingPartyTrust = fixture.trust,
            remoteResourceRetriever = {
                fetched = it
                if (it.url != QesPreparationFixture.REQUEST_URI) error("Unexpected fetch: ${it.url}")
                expectedParameters = parameters.copy(walletNonce = it.requestObjectParameters?.walletNonce)
                returnedJar = fixture.sign(expectedParameters)
                returnedJar
            },
        )
        val input = when (transport) {
            "direct" -> jar
            "request" -> fixture.invocation(request = jar)
            else -> fixture.invocation(method = if (transport == "request_uri_post") JarRequestParameters.RequestUriMethod.POST else null)
        }
        val resolved = holder.startAuthorizationResponsePreparation(input).getOrThrow()
        resolved.request.parameters shouldBe expectedParameters
        resolved.credentialPresentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.DCQLRequest>()
            .dcqlQuery shouldBe parameters.dcqlQuery
        resolved.request.parameters.transactionDataDecoded shouldBe listOf(fixture.transaction)
        resolved.request.parameters.transactionData!!.single().content shouldBe transaction
        resolved.request.shouldBeInstanceOf<RequestParametersFrom.Jws<*>>().jws.toString() shouldBe returnedJar
        if (transport.startsWith("request_uri")) {
            fetched.shouldNotBeNull().apply {
                url shouldBe QesPreparationFixture.REQUEST_URI
                method shouldBe if (transport == "request_uri_post") HttpMethod.Post else HttpMethod.Get
                headers[HttpHeaders.Accept] shouldBe MediaTypes.Application.AUTHZ_REQ_JWT
            }
        } else fetched shouldBe null
    }

    "verifies an X.509 request against its certificate and configured trust anchor" {
        val fixture = QesPreparationFixture()
        val ca = TestCertificateAuthority()
        val signer = ca.issue()
        val hash = signer.getCertificate()!!.encodeToDer().sha256().encodeToString(Base64UrlStrict)
        val request = fixture.parameters.copy(clientId = "x509_hash:$hash")
        val jar = fixture.sign(request, signer)
        OpenId4VpHolder(relyingPartyTrust = setOf(RelyingPartyTrust.Certificates { setOf(ca.certificate) }))
            .startAuthorizationResponsePreparation(jar).getOrThrow().request.parameters shouldBe request
        OpenId4VpHolder(relyingPartyTrust = setOf(RelyingPartyTrust.Certificates { setOf(TestCertificateAuthority().certificate) }))
            .startAuthorizationResponsePreparation(jar).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    "requires configured relying-party trust" {
        val fixture = QesPreparationFixture()
        OpenId4VpHolder().startAuthorizationResponsePreparation(fixture.sign()).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        OpenId4VpHolder(relyingPartyTrust = emptySet())
            .startAuthorizationResponsePreparation(fixture.sign()).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        OpenId4VpHolder(relyingPartyTrust = setOf(RelyingPartyTrust.PreRegisteredClients { null }))
            .startAuthorizationResponsePreparation(fixture.sign()).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    "the parsed-request overload validates QES and retains the same preparation state" {
        val fixture = QesPreparationFixture()
        val request = RequestParametersFrom.Jws(
            jws = JwsCompact(fixture.sign()),
            parameters = fixture.parameters,
        )
        fixture.holder.startAuthorizationResponsePreparation(request).getOrThrow().request shouldBe request
        fixture.holder.startAuthorizationResponsePreparation(request.copy(
            parameters = fixture.parameters.copy(nonce = "changed-after-signing"),
        )).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    "ordinary presentations keep their existing optional-trust behavior" {
        val fixture = QesPreparationFixture()
        val request = fixture.parameters.copy(
            transactionData = null,
            state = null,
            dcqlQuery = joseCompliantSerializer.decodeFromString<DCQLQuery>(
                """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]}}]}""",
            ),
        )
        OpenId4VpHolder().startAuthorizationResponsePreparation(fixture.sign(request))
            .getOrThrow().request.parameters shouldBe request
    }

    "approval transactions keep general OpenID4VP validation instead of the Annex A signing profile" {
        val fixture = QesPreparationFixture()
        val approval = joseCompliantSerializer.decodeFromString<TransactionData>(
            """{
                "type":"https://cloudsignatureconsortium.org/2025/qes-approval",
                "credential_ids":["pid"], "numSignatures":1, "signatureQualifier":"eu_eidas_qes",
                "documentDigests":[{"label":"Contract","hash":"AQID"}],
                "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
            }""",
        )
        val request = fixture.parameters.copy(
            state = null,
            dcqlQuery = joseCompliantSerializer.decodeFromString<DCQLQuery>(
                """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]}}]}""",
            ),
            transactionData = listOf(approval.toBase64UrlJsonString()),
        )
        OpenId4VpHolder().startAuthorizationResponsePreparation(joseCompliantSerializer.encodeToString(request))
            .getOrThrow().request.parameters shouldBe request
    }

    listOf("empty credential_ids", "unknown query", "empty signatureRequests", "missing transaction_data", "state")
        .asData(nameFn = { "authenticates the RP before rejecting $it" }) test { invalid ->
        val fixture = QesPreparationFixture()
        val request = fixture.parameters.copy(
            state = if (invalid == "state") null else fixture.parameters.state,
            transactionData = when (invalid) {
                "empty credential_ids" -> listOf(fixture.transaction.copy(credentialIds = emptySet()).toBase64UrlJsonString())
                "unknown query" -> listOf(fixture.transaction.copy(credentialIds = setOf("unknown")).toBase64UrlJsonString())
                "empty signatureRequests" -> listOf(fixture.transaction.copy(signatureRequests = emptyList()).toBase64UrlJsonString())
                "missing transaction_data" -> null
                else -> fixture.parameters.transactionData
            },
        )
        fixture.holder.startAuthorizationResponsePreparation(fixture.sign(request, EphemeralKeyWithoutCert()))
            .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
            .message.shouldNotBeNull() shouldContain "request object not signed by a key registered for this client_id"
        OpenId4VpHolder(relyingPartyTrust = setOf(RelyingPartyTrust.PreRegisteredClients { null }))
            .startAuthorizationResponsePreparation(fixture.sign(request))
            .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
            .message.shouldNotBeNull() shouldContain "not a pre-registered relying party"
        val authenticatedFailure = fixture.holder.startAuthorizationResponsePreparation(fixture.sign(request)).exceptionOrNull()
        if (invalid == "state") authenticatedFailure.shouldBeInstanceOf<InvalidRequest>()
            .message.shouldNotBeNull() shouldContain "nonce and state"
        else authenticatedFailure.shouldBeInstanceOf<InvalidTransactionData>()
    }

    listOf("valid", "bad signature", "bad transaction", "bad typ", "malformed transaction")
        .asData(nameFn = { "consumes wallet_nonce at entry for a $it request and rejects its replay" }) test { outcome ->
        val fixture = QesPreparationFixture()
        val walletNonce = "single-attempt-nonce"
        val nonceStore = DefaultMapStore<String, String>()
        nonceStore.put(walletNonce, walletNonce)
        var lookups = 0
        val holder = OpenId4VpHolder(
            walletNonceMapStore = nonceStore,
            relyingPartyTrust = setOf(RelyingPartyTrust.PreRegisteredClients {
                lookups++
                nonceStore.get(walletNonce) shouldBe null
                setOf(fixture.signer.jsonWebKey)
            }),
        )
        val parameters = fixture.parameters.copy(
            walletNonce = walletNonce,
            transactionData = when (outcome) {
                "bad transaction" -> listOf(fixture.transaction.copy(signatureRequests = emptyList()).toBase64UrlJsonString())
                "malformed transaction" -> listOf(JsonPrimitive("!"))
                else -> fixture.parameters.transactionData
            },
        )
        val request = RequestParametersFrom.Jws(
            jws = JwsCompact(fixture.sign(
                payload = parameters,
                keyMaterial = if (outcome == "bad signature") EphemeralKeyWithoutCert() else fixture.signer,
                typ = if (outcome == "bad typ") "JWT" else JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            )),
            parameters = parameters,
        )
        val result = holder.startAuthorizationResponsePreparation(request)
        when (outcome) {
            "valid" -> result.getOrThrow().request shouldBe request
            "bad transaction", "malformed transaction" -> result.exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
            else -> result.exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        }
        nonceStore.get(walletNonce) shouldBe null
        val expectedLookups = if (outcome == "bad typ" || outcome == "malformed transaction") 0 else 1
        lookups shouldBe expectedLookups
        holder.startAuthorizationResponsePreparation(request)
            .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
            .message.shouldNotBeNull() shouldContain "wallet_nonce from request not known to us"
        lookups shouldBe expectedLookups
    }

    "rejects a request signed by a key other than the registered relying party's key" {
        val fixture = QesPreparationFixture()
        fixture.holder.startAuthorizationResponsePreparation(fixture.sign(keyMaterial = EphemeralKeyWithoutCert()))
            .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    listOf("payload", "signature").asData(nameFn = { "rejects a tampered $it" }) test { part ->
        val fixture = QesPreparationFixture()
        val segments = fixture.sign().split('.').toMutableList()
        if (part == "payload") {
            segments[1] = segments[1].decodeToByteArray(Base64UrlStrict).decodeToString()
                .replace("\"nonce\":\"nonce\"", "\"nonce\":\"tampered\"")
                .encodeToByteArray().encodeToString(Base64UrlStrict)
        } else {
            segments[2] = segments[2].decodeToByteArray(Base64UrlStrict).also {
                it[0] = (it[0].toInt() xor 1).toByte()
            }.encodeToString(Base64UrlStrict)
        }
        fixture.holder.startAuthorizationResponsePreparation(segments.joinToString("."))
            .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    listOf("json", "url", "plain request_uri", "unavailable request_uri", "wrong typ", "mismatched client_id")
        .asData(nameFn = { "rejects $it" }) test { invalid ->
        val fixture = QesPreparationFixture()
        val json = joseCompliantSerializer.encodeToString(fixture.parameters)
        val holder = OpenId4VpHolder(
            relyingPartyTrust = fixture.trust,
            remoteResourceRetriever = { if (invalid == "plain request_uri") json else null },
        )
        val input = when (invalid) {
            "json" -> json
            "url" -> URLBuilder("openid4vp://authorize").apply {
                fixture.parameters.encodeToParameters().forEach { parameters.append(it.key, it.value) }
            }.buildString()
            "wrong typ" -> fixture.sign(typ = "JWT")
            "mismatched client_id" -> fixture.invocation(request = fixture.sign(), clientId = "another-client")
            else -> fixture.invocation()
        }
        holder.startAuthorizationResponsePreparation(input).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    listOf("nonce", "state", "dcql_query", "response_type", "response_mode", "client_id", "redirect_uri scheme", "custom scheme")
        .asData(nameFn = { "rejects invalid QES authorization parameter: $it" }) test { invalid ->
        val fixture = QesPreparationFixture()
        val request = fixture.parameters.let {
            when (invalid) {
                "nonce" -> it.copy(nonce = null)
                "state" -> it.copy(state = null)
                "dcql_query" -> it.copy(dcqlQuery = null)
                "response_type" -> it.copy(responseType = "vp_token id_token")
                "response_mode" -> it.copy(responseMode = null)
                "client_id" -> it.copy(clientId = null)
                "redirect_uri scheme" -> it.copy(clientId = "redirect_uri:https://rp.example/response")
                else -> it.copy(clientId = "entity_id:https://rp.example")
            }
        }
        // A permissive custom trust callback must not bypass the holder's signature verification requirement.
        OpenId4VpHolder(relyingPartyTrust = fixture.trust + RelyingPartyTrust.Custom { })
            .startAuthorizationResponsePreparation(fixture.sign(request)).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
    }

    listOf("missing", "empty", "malformed", "unknown type", "empty credential_ids", "unknown query", "non-X.509 query", "empty signatureRequests")
        .asData(nameFn = { "rejects invalid QES transaction data: $it" }) test { invalid ->
        val fixture = QesPreparationFixture()
        val data = when (invalid) {
            "missing" -> null
            "empty" -> emptyList()
            "malformed" -> listOf(JsonPrimitive("!"))
            "unknown type" -> listOf(JsonPrimitive("""{"type":"unknown","credential_ids":["certificate"]}"""
                .encodeToByteArray().encodeToString(Base64UrlStrict)))
            "empty credential_ids" -> listOf(fixture.transaction.copy(credentialIds = emptySet()).toBase64UrlJsonString())
            "unknown query" -> listOf(fixture.transaction.copy(credentialIds = setOf("unknown")).toBase64UrlJsonString())
            "empty signatureRequests" -> listOf(fixture.transaction.copy(signatureRequests = emptyList()).toBase64UrlJsonString())
            else -> fixture.parameters.transactionData
        }
        val request = fixture.parameters.copy(
            transactionData = data,
            dcqlQuery = if (invalid == "non-X.509 query") joseCompliantSerializer.decodeFromString<DCQLQuery>(
                """{"credentials":[{"id":"certificate","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]}}]}"""
            ) else fixture.parameters.dcqlQuery,
        )
        fixture.holder.startAuthorizationResponsePreparation(fixture.sign(request)).exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
    }
}

private class QesPreparationFixture {
    val signer = EphemeralKeyWithoutCert()
    val trust = setOf(RelyingPartyTrust.PreRegisteredClients { clientId ->
        if (clientId == CLIENT_ID) setOf(signer.jsonWebKey) else null
    })
    val holder = OpenId4VpHolder(relyingPartyTrust = trust)
    val transaction = QesRequest(
        credentialIds = setOf("certificate"),
        signatureRequests = listOf(QesSignatureRequest(
            document = DocumentReference(label = "Contract", href = "https://rp.example/contract.pdf"),
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        )),
    )
    val parameters = AuthenticationRequestParameters(
        responseType = OpenIdConstants.VP_TOKEN,
        clientId = CLIENT_ID,
        responseMode = OpenIdConstants.ResponseMode.DirectPost,
        responseUrl = "https://rp.example/response",
        nonce = "nonce",
        state = "state",
        dcqlQuery = joseCompliantSerializer.decodeFromString<DCQLQuery>(
            """{"credentials":[{"id":"certificate","format":"https://cloudsignatureconsortium.org/2025/x509","meta":{"certificatePolicies":["0.4.0.194112.1"]}}]}"""
        ),
        transactionData = listOf(transaction.toBase64UrlJsonString()),
    )

    suspend fun sign(
        payload: AuthenticationRequestParameters = parameters,
        keyMaterial: KeyMaterial = signer,
        typ: String = JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
    ): String = SignJwt<AuthenticationRequestParameters>(keyMaterial, JwsHeaderCertOrJwk())(
        typ, payload, AuthenticationRequestParameters.serializer(),
    ).getOrThrow().toString()

    fun invocation(
        request: String? = null,
        clientId: String = CLIENT_ID,
        method: JarRequestParameters.RequestUriMethod? = null,
    ): String = URLBuilder("openid4vp://authorize").apply {
        parameters.append("client_id", clientId)
        if (request != null) parameters.append("request", request)
        else parameters.append("request_uri", REQUEST_URI)
        method?.let { parameters.append("request_uri_method", if (it == JarRequestParameters.RequestUriMethod.POST) "post" else "get") }
    }.buildString()

    companion object {
        const val CLIENT_ID = "qes-relying-party"
        const val REQUEST_URI = "https://rp.example/request/1"
    }
}
