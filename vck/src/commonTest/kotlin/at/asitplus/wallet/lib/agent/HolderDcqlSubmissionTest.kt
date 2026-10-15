package at.asitplus.wallet.lib.agent

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

val HolderDcqlSubmissionTest by matrixSuite {
    "explicit DCQL submissions" - {
        listOf("metadata", "missing-claim", "disclosures", "empty", "multiple", "unknown", "later-invalid")
            .asData(nameFn = { "rejects explicit $it submissions before signing" }) test { scenario ->
                val fixture = holderSubmissionFixture()
                var query = holderSubmissionQuery()
                val matching = (fixture.agent.matchPresentationRequestAgainstCredentialStore(
                    CredentialPresentationRequest.DCQLRequest(query),
                ).getOrThrow() as DCQLMatchingResult).matchingResult.credentialQueryMatches
                val id = query.credentials.single().id
                var submissions = matching
                when (scenario) {
                    "metadata" -> query = holderSubmissionQuery(vct = "different-credential")
                    "missing-claim" -> query = holderSubmissionQuery(claims = """[{"path":["missing"]}]""")
                    "disclosures" -> submissions = matching.mapValues { (_, options) ->
                        options.map { it.copy(matchingResult = AllClaimsMatchingResult) }
                    }
                    "empty" -> submissions = mapOf(id to emptyList())
                    "multiple" -> submissions = mapOf(id to matching.getValue(id) + matching.getValue(id))
                    "unknown" -> submissions = mapOf(DCQLCredentialQueryIdentifier("unknown") to matching.getValue(id))
                    "later-invalid" -> {
                        val otherId = DCQLCredentialQueryIdentifier("other")
                        val other = holderSubmissionQuery(vct = "different-credential").credentials.single()
                            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>().copy(id = otherId)
                        query = query.copy(credentials = DCQLCredentialQueryList(query.credentials.single(), other))
                        submissions = matching + (otherId to matching.getValue(id))
                    }
                }
                fixture.agent.createPresentation(
                    request = PresentationRequestParameters(nonce = "nonce", audience = "https://verifier.example.com"),
                    credentialPresentation = CredentialPresentationRequest.DCQLRequest(query).toCredentialPresentation(submissions),
                ).isFailure shouldBe true
                fixture.signingCalls() shouldBe 0
            }

        "accepts an explicit alternate claim set" {
            val fixture = holderSubmissionFixture()
            val query = holderSubmissionQuery(
                claims = """[{"id":"family","path":["family_name"]},{"id":"given","path":["given_name"]}]""",
                claimSets = """[["family"],["given"]]""",
            )
            val alternate = holderSubmissionQuery(claims = """[{"path":["given_name"]}]""")
            val submissions = (fixture.agent.matchPresentationRequestAgainstCredentialStore(
                CredentialPresentationRequest.DCQLRequest(alternate),
            ).getOrThrow() as DCQLMatchingResult).matchingResult.credentialQueryMatches
            val verifier = NonceChallengeVerifier(verifierId = "https://verifier.example.com")
            val request = verifier.createPresentationRequest()
            val response = fixture.agent.createPresentation(
                request = request,
                credentialPresentation = CredentialPresentationRequest.DCQLRequest(query).toCredentialPresentation(submissions),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
            val presentation = response.verifiablePresentations.values.single().single()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
            val verified = verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(presentation.sdJwt).getOrThrow()
            verified.reconstructedJsonObject["family_name"].shouldBeNull()
            fixture.signingCalls() shouldBe 1
        }
    }
}

private class HolderSubmissionFixture(val agent: Holder, val signingCalls: () -> Int)

private suspend fun holderSubmissionFixture(): HolderSubmissionFixture {
    val key = EphemeralKeyWithoutCert()
    val signer = SignJwt<KeyBindingJws>(key, JwsHeaderNone())
    var calls = 0
    val holder = HolderAgent(
        keyMaterial = key,
        signKeyBinding = SignJwtFun { type, payload, serializer ->
            calls++
            signer(type, payload, serializer)
        },
    )
    DummyCredentialDataProvider.issueAndStoreSdJwt(holder, key, IssuerAgent(
        keyMaterial = EphemeralKeyWithSelfSignedCert(),
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default,
    ))
    return HolderSubmissionFixture(holder) { calls }
}

private fun holderSubmissionQuery(
    vct: String = ConstantIndex.AtomicAttribute2023.sdJwtType,
    claims: String = """[{"path":["family_name"]}]""",
    claimSets: String? = null,
): DCQLQuery = Json.decodeFromString("""{
    "credentials":[{
        "id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["$vct"]},"claims":$claims
        ${claimSets?.let { ",\"claim_sets\":$it" }.orEmpty()}
    }]
}""")
