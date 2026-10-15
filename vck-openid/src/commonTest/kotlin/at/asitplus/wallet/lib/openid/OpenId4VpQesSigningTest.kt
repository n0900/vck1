package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.csc.api.CredentialInfo
import at.asitplus.csc.api.OperationMode
import at.asitplus.csc.api.SignHashRequestParameters
import at.asitplus.csc.api.SignHashResponseParameters
import at.asitplus.csc.api.collection_entries.CertificateParameters
import at.asitplus.csc.api.collection_entries.KeyParameters
import at.asitplus.csc.bindings.X509KeyInfo
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.ConformanceLevel
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.sha256
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.*
import at.asitplus.openid.toBase64UrlJsonString
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.rqes.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

val OpenId4VpQesSigningTest by matrixSuite {
    "passes the CSC signHash request to the callback and retains local document correlation" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val original = fixture.preparation.transaction.signatureRequests.single().copy(
            signingAlgorithm = signingAlgorithm,
            adesParameters = AdesParameters(SignatureFormat.PADES, ConformanceLevel.ADESBB),
            responseUri = "https://rp.example/signature-result",
        )
        val state = fixture.prepare(transactions = listOf(fixture.preparation.transaction.copy(signatureRequests = listOf(original))))
        fixture.calls shouldBe emptyList()
        val result = fixture.execute(state, credential).getOrThrow()
        result.credentialPresentations.verifiablePresentations shouldBe emptyMap()
        val signed = result.signingResults.single()
        signed.preparedDocument shouldBe state.preparedQesDocuments.single()
        signed.credentialQueryId shouldBe certificateId
        signed.response shouldBe completedResponse
        val request = fixture.calls.single()
        signed.request shouldBe request
        request.hashes.single().toList() shouldBe state.preparedQesDocuments.single().preparation.dtbsr.value.toList()
        request.hashAlgorithmOid shouldBe Digest.SHA256.oid
        request.signAlgoOid shouldBe signingAlgorithm.signAlgo
        request.sad shouldBe null
        request.operationMode shouldBe OperationMode.SYNCHRONOUS
        request.credentialId shouldBe credential.credentialId
        val json = joseCompliantSerializer.encodeToJsonElement(SignHashRequestParameters.serializer(), request).jsonObject
        json["credentialID"] shouldBe JsonPrimitive(credential.credentialId)
        json["hashes"] shouldBe JsonArray(listOf(JsonPrimitive(Base64.encode(request.hashes.single()))))
        json["hashAlgorithmOID"] shouldBe JsonPrimitive(Digest.SHA256.oid.toString())
        json["signAlgo"] shouldBe JsonPrimitive(signingAlgorithm.signAlgo.toString())
    }

    "returns results in request order despite reversed choices and retains non-QES transaction indices" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val approval = joseCompliantSerializer.decodeFromString<TransactionData>(approvalJson)
        val transaction = fixture.preparation.transaction
        val state = fixture.prepare(transactions = listOf(
            approval,
            transaction.copy(signatureRequests = List(2) { transaction.signatureRequests.single() }),
            transaction,
        ), query = mixedQuery())
        val key = EphemeralKeyWithoutCert()
        val agent = HolderAgent(key)
        DummyCredentialDataProvider.issueAndStoreSdJwt(agent, key)
        val submissions = fixture.ordinarySubmissions(state, agent)
        val holder = fixture.holder(agent)
        val choices = state.preparedQesDocuments.reversed().map {
            QesDocumentSigningChoice(it.transactionIndex, it.signatureRequestIndex, certificateId, signingAlgorithm)
        }
        val result = holder.executeQesSigning(state, submissions, mapOf(certificateId to credential), choices).getOrThrow()
        result.signingResults.map { it.preparedDocument.let { it.transactionIndex to it.signatureRequestIndex } } shouldBe
                listOf(1 to 0, 1 to 1, 2 to 0)
        fixture.calls.size shouldBe 3
    }

    "mixed DCQL preserves nonce audience original transaction data and independent approval binding" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val key = EphemeralKeyWithoutCert()
        val agent = HolderAgent(key)
        DummyCredentialDataProvider.issueAndStoreSdJwt(agent, key)
        val approval = joseCompliantSerializer.decodeFromString<TransactionData>(approvalJson)
        val state = fixture.prepare(transactions = listOf(fixture.preparation.transaction, approval), query = mixedQuery())
        val submissions = fixture.ordinarySubmissions(state, agent)
        val result = fixture.holder(agent).executeQesSigning(
            state, submissions, mapOf(certificateId to credential), listOf(defaultChoice),
        ).getOrThrow()
        val presentation = result.credentialPresentations.verifiablePresentations.getValue(pidId).single()
            .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
        presentation.sdJwt.keyBindingJws.shouldNotBeNull().payload.apply {
            challenge shouldBe state.request.parameters.nonce
            audience shouldBe state.audience
            qesApproval.shouldNotBeNull().toList() shouldBe
                    state.request.parameters.transactionData!![1].content.encodeToByteArray().sha256().toList()
            transactionDataHashes.shouldNotBeNull().map { it.toList() } shouldBe
                    state.request.parameters.transactionData!!.map { it.content.encodeToByteArray().sha256().toList() }
        }
        fixture.calls.size shouldBe 1
    }

    listOf("missing", "duplicate", "unknown-index", "unknown-query", "missing-credential", "extra-credential",
        "missing-prepared", "duplicate-prepared", "digest-length", "digest-algorithm", "algorithm", "no-algorithm",
        "key-disabled", "status", "no-certificate", "qualifier", "empty-credential-id", "credential-id", "unsupported-algorithm",
        "key-curve", "fingerprint", "weak-fingerprint", "policy", "key-configuration", "claims", "required-ordinary",
        "expired", "not-yet-valid"
    ).asData(nameFn = { "rejects $it before QTSP invocation" }) test { scenario ->
        val fixture = QesSigningFixture()
        var credential = fixture.credential()
        var state = fixture.prepare()
        var credentials = mapOf(certificateId to credential)
        var choices = listOf(defaultChoice)
        var query = state.request.parameters.dcqlQuery!!
        val originalQuery = query.credentials.single() as DCQLX509CredentialQuery
        when (scenario) {
            "missing" -> choices = emptyList()
            "duplicate" -> choices = choices + choices
            "unknown-index" -> choices = listOf(defaultChoice.copy(transactionIndex = 20))
            "unknown-query" -> choices = listOf(defaultChoice.copy(credentialQueryId = pidId))
            "missing-credential" -> credentials = emptyMap()
            "extra-credential" -> credentials = credentials + (pidId to credential)
            "missing-prepared" -> state = state.copy(preparedQesDocuments = emptyList())
            "duplicate-prepared" -> state = state.copy(preparedQesDocuments = state.preparedQesDocuments + state.preparedQesDocuments)
            "digest-length", "digest-algorithm" -> state = state.copy(preparedQesDocuments = state.preparedQesDocuments.map {
                it.copy(preparation = QesDocumentPreparation(if (scenario == "digest-length") Hash(byteArrayOf(1), Digest.SHA256.oid)
                    else Hash(ByteArray(48), Digest.SHA384.oid)))
            })
            "algorithm" -> choices = listOf(defaultChoice.copy(signingAlgorithm = SigningAlgorithm(X509SignatureAlgorithm.ES384.oid)))
            "no-algorithm" -> choices = listOf(defaultChoice.copy(signingAlgorithm = null))
            "key-disabled" -> credential = credential.copy(credentialInfo = credential.credentialInfo.copy(
                keyParameters = credential.credentialInfo.keyParameters.copy(status = KeyParameters.KeyStatusOptions.DISABLED)))
            "status" -> credential = credential.copy(credentialInfo = credential.credentialInfo.copy(
                certParameters = credential.credentialInfo.certParameters!!.copy(status = CertificateParameters.CertStatus.REVOKED)))
            "no-certificate" -> credential = credential.copy(credentialInfo = credential.credentialInfo.copy(certParameters = null))
            "qualifier" -> credential = credential.copy(credentialInfo = credential.credentialInfo.copy(signatureQualifier = null))
            "empty-credential-id" -> credential = credential.copy(credentialId = "")
            "credential-id" -> credential = credential.copy(credentialId = "other")
            "unsupported-algorithm" -> choices = listOf(defaultChoice.copy(signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.3.4"))))
            "key-curve" -> credential = credential.copy(credentialInfo = credential.credentialInfo.copy(
                keyParameters = credential.credentialInfo.keyParameters.copy(curve = null)))
            "expired" -> credential = fixture.credential(validFrom = Clock.System.now() - 10.minutes)
            "not-yet-valid" -> credential = fixture.credential(validFrom = Clock.System.now() + 10.minutes)
            "fingerprint", "weak-fingerprint", "policy", "key-configuration", "claims" -> {
                val meta = originalQuery.meta
                val changed = when (scenario) {
                    "fingerprint" -> originalQuery.copy(meta = meta.copy(certificateFingerprints = listOf(Hash(ByteArray(32), Digest.SHA256.oid))))
                    "weak-fingerprint" -> originalQuery.copy(meta = meta.copy(certificateFingerprints = listOf(Hash(ByteArray(20), Digest.SHA1.oid))))
                    "policy" -> originalQuery.copy(meta = meta.copy(certificatePolicies = listOf("1.2.3.4")))
                    "key-configuration" -> originalQuery.copy(meta = meta.copy(keys = listOf(X509KeyInfo("1.2.3.4", len = 2048))))
                    else -> originalQuery.copy(claims = DCQLClaimsQueryList(listOf(DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer("subject"),
                    )).toNonEmptyList()))
                }
                query = query.copy(credentials = DCQLCredentialQueryList(changed))
            }
            "required-ordinary" -> query = mixedQuery()
        }
        if (query != state.request.parameters.dcqlQuery) state = fixture.prepare(query = query)
        if (credential != credentials[certificateId] && scenario !in setOf("missing-credential", "extra-credential"))
            credentials = mapOf(certificateId to credential)
        fixture.holder().executeQesSigning(state, emptyMap(), credentials, choices).exceptionOrNull()
            .shouldBeInstanceOf<InvalidTransactionData>()
        fixture.calls shouldBe emptyList()
    }

    "matches policy and fingerprint alternatives and EC key configuration against the leaf certificate" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val certificate = credential.credentialInfo.certParameters!!.certificates!!.first()
        val query = fixture.preparation.parameters.dcqlQuery!!
        val x509 = query.credentials.single() as DCQLX509CredentialQuery
        val state = fixture.prepare(query = query.copy(credentials = DCQLCredentialQueryList(x509.copy(meta = x509.meta.copy(
            certificateFingerprints = listOf(Hash(ByteArray(32), Digest.SHA256.oid), Hash(certificate.encodeToDer().sha256(), Digest.SHA256.oid)),
            certificatePolicies = listOf("1.2.3.4", policyOid),
            keys = listOf(X509KeyInfo(signingAlgorithm.signAlgo.toString(), curve = credential.credentialInfo.keyParameters.curve.toString())),
        )))))
        fixture.execute(state, credential).getOrThrow().signingResults.size shouldBe 1
    }

    "credential_ids alternatives authorize exactly the app-selected query" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val originalQuery = fixture.preparation.parameters.dcqlQuery!!.credentials.single() as DCQLX509CredentialQuery
        val query = DCQLQuery(DCQLCredentialQueryList(originalQuery, originalQuery.copy(id = pidId)),
            listOf(DCQLCredentialSetQuery(listOf(listOf(certificateId), listOf(pidId)).toNonEmptyList())).toNonEmptyList())
        val transaction = fixture.preparation.transaction.copy(credentialIds = setOf(certificateId.string, pidId.string))
        val state = fixture.prepare(query = query, transactions = listOf(transaction))
        val result = fixture.holder().executeQesSigning(state, emptyMap(), mapOf(pidId to credential),
            listOf(defaultChoice.copy(credentialQueryId = pidId))).getOrThrow()
        result.signingResults.single().credentialQueryId shouldBe pidId
    }

    listOf(SignHashResponseParameters(), SignHashResponseParameters(responseId = "pending"),
        SignHashResponseParameters(signatures = listOf("AQ==", "Ag==")), SignHashResponseParameters(signatures = listOf("")),
        SignHashResponseParameters(signatures = listOf("?!")), SignHashResponseParameters(signatures = listOf("AQ")),
        SignHashResponseParameters(signatures = listOf("__8=")), SignHashResponseParameters(signatures = listOf("AR==")),
        completedResponse.copy(responseId = "ambiguous")
    ).asData(nameFn = { "rejects incomplete or malformed QTSP response $it" }) test { response ->
        val fixture = QesSigningFixture(response = response)
        fixture.execute(fixture.prepare(), fixture.credential()).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        fixture.calls.size shouldBe 1
    }

    "does not retry or continue after a later QTSP failure" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val transaction = fixture.preparation.transaction
        val state = fixture.prepare(transactions = listOf(transaction.copy(signatureRequests = List(3) { transaction.signatureRequests.single() })))
        val cause = IllegalStateException("QTSP failed")
        fixture.callback = { if (fixture.calls.size == 2) catching { throw cause } else catching { completedResponse } }
        fixture.execute(state, credential).exceptionOrNull() shouldBe cause
        fixture.calls.size shouldBe 2
    }

    "propagates coroutine cancellation without another QTSP invocation" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val state = fixture.prepare()
        fixture.callback = { throw CancellationException("cancelled") }
        shouldThrow<CancellationException> { fixture.execute(state, credential) }
        fixture.calls.size shouldBe 1
    }

    "preserves user signature cancellation" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val state = fixture.prepare()
        val cancellation = UnlockFailed("user cancelled")
        fixture.callback = { catching { throw cancellation } }
        fixture.execute(state, credential).exceptionOrNull() shouldBe cancellation
        fixture.calls.size shouldBe 1
    }

    listOf(X509SignatureAlgorithm.PS256, X509SignatureAlgorithm.RS256).asData(
        nameFn = { "forwards $it parameters and rejects a changed requested algorithm" },
    ) test { rsaAlgorithm ->
        val fixture = QesSigningFixture()
        val algorithm = SigningAlgorithm(rsaAlgorithm.oid, rsaAlgorithm.parameters.single())
        val key = EphemeralKeyWithoutCert(EphemeralKey { rsa {} }.getOrThrow())
        val credential = fixture.credential(key = key, algorithm = algorithm)
        val transaction = fixture.preparation.transaction.copy(signatureRequests = listOf(
            fixture.preparation.transaction.signatureRequests.single().copy(signingAlgorithm = algorithm),
        ))
        val originalQuery = fixture.preparation.parameters.dcqlQuery!!
        val x509 = originalQuery.credentials.single() as DCQLX509CredentialQuery
        val rsaKey = key.publicKey as CryptoPublicKey.RSA
        val state = fixture.prepare(transactions = listOf(transaction), query = originalQuery.copy(
            credentials = DCQLCredentialQueryList(x509.copy(meta = x509.meta.copy(
                keys = listOf(X509KeyInfo(rsaKey.oid.toString(), len = rsaKey.bits.number.toInt())),
            ))),
        ))
        fixture.holder().executeQesSigning(state, emptyMap(), mapOf(certificateId to credential),
            listOf(defaultChoice.copy(signingAlgorithm = null))).getOrThrow()
        val request = fixture.calls.single()
        request.signAlgoParams shouldBe algorithm.signAlgoParams
        request.hashes.single().toList() shouldBe state.preparedQesDocuments.single().preparation.dtbsr.value.toList()
        fixture.calls.clear()
        val changed = if (rsaAlgorithm is X509SignatureAlgorithm.RSAPSS)
            algorithm.copy(signAlgoParams = X509SignatureAlgorithm.PS384.parameters.single())
        else SigningAlgorithm(X509SignatureAlgorithm.RS384.oid, X509SignatureAlgorithm.RS384.parameters.single())
        fixture.holder().executeQesSigning(state, emptyMap(), mapOf(certificateId to credential),
            listOf(defaultChoice.copy(signingAlgorithm = changed))).exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
        fixture.calls shouldBe emptyList()
    }

    listOf("wrong-disclosures", "empty", "multiple", "unknown").asData(
        nameFn = { "validates ordinary $it submissions before QTSP signing" },
    ) test { scenario ->
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        val key = EphemeralKeyWithoutCert()
        val agent = HolderAgent(key)
        DummyCredentialDataProvider.issueAndStoreSdJwt(agent, key)
        val state = fixture.prepare(query = mixedQuery())
        val original = fixture.ordinarySubmissions(state, agent).getValue(pidId)
        val submissions = when (scenario) {
            "wrong-disclosures" -> mapOf(pidId to original.map { it.copy(matchingResult = DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) })
            "empty" -> mapOf(pidId to emptyList())
            "multiple" -> mapOf(pidId to original + original)
            else -> mapOf(DCQLCredentialQueryIdentifier("unknown") to original)
        }
        fixture.holder(agent).executeQesSigning(state, submissions, mapOf(certificateId to credential),
            listOf(defaultChoice)).exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
        fixture.calls shouldBe emptyList()
    }

    "routes provider-local credential IDs through their selected CSC callbacks" {
        val fixture = QesSigningFixture()
        val first = fixture.credential()
        val second = fixture.credential()
        first.credentialId shouldBe second.credentialId
        val routed = mutableListOf<String>()
        val query = fixture.preparation.parameters.dcqlQuery!!.credentials.single() as DCQLX509CredentialQuery
        val transaction = fixture.preparation.transaction
        val state = fixture.prepare(
            query = DCQLQuery(DCQLCredentialQueryList(query, query.copy(id = pidId))),
            transactions = listOf(transaction, transaction.copy(credentialIds = setOf(pidId.string))),
        )
        val result = fixture.holder().executeQesSigning(
            preparationState = state,
            credentialSubmissions = emptyMap(),
            signingCredentials = mapOf(
                certificateId to first.copy(signHash = { request ->
                    routed += "first"
                    request.credentialId shouldBe first.credentialId
                    catching { completedResponse }
                }),
                pidId to second.copy(signHash = { request ->
                    routed += "second"
                    request.credentialId shouldBe second.credentialId
                    catching { completedResponse.copy(signatures = listOf("BQYHCA==")) }
                }),
            ),
            signingChoices = listOf(defaultChoice, defaultChoice.copy(transactionIndex = 1, credentialQueryId = pidId)),
        ).getOrThrow()
        routed shouldBe listOf("first", "second")
        result.signingResults.map { it.response.signatures!!.single() } shouldBe listOf("AQIDBA==", "BQYHCA==")
        fixture.calls shouldBe emptyList()
    }

    "allows the application to add SAD while preserving the standard signing request" {
        val fixture = QesSigningFixture()
        val credential = fixture.credential()
        var authorized: SignHashRequestParameters? = null
        fixture.callback = { request -> catching {
            authorized = request.copy(sad = "application-SAD")
            completedResponse
        } }
        val result = fixture.execute(fixture.prepare(), credential).getOrThrow()
        val request = result.signingResults.single().request
        request.sad shouldBe null
        authorized.shouldNotBeNull().apply {
            sad shouldBe "application-SAD"
            copy(sad = null) shouldBe request
        }
    }
}

private val certificateId = DCQLCredentialQueryIdentifier("certificate")
private val pidId = DCQLCredentialQueryIdentifier("pid")
private const val policyOid = "0.4.0.194112.1"
private val signingAlgorithm = SigningAlgorithm(X509SignatureAlgorithm.ES256.oid)
private val defaultChoice = QesDocumentSigningChoice(0, 0, certificateId, signingAlgorithm)
private val completedResponse = SignHashResponseParameters(signatures = listOf("AQIDBA=="))
private val approvalJson = """{
    "type":"https://cloudsignatureconsortium.org/2025/qes-approval","credential_ids":["pid"],
    "signatureQualifier":"eu_eidas_qes","numSignatures":1,
    "documentDigests":[{"hash":"AQID"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
}"""

private fun mixedQuery(): DCQLQuery = joseCompliantSerializer.decodeFromString("""{
    "credentials":[
      {"id":"certificate","format":"https://cloudsignatureconsortium.org/2025/x509","meta":{}},
      {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["${ConstantIndex.AtomicAttribute2023.sdJwtType}"]},
       "claims":[{"path":["family_name"]}]}
    ]
}""")

private class QesSigningFixture(val response: SignHashResponseParameters = completedResponse) {
    val preparation = QesPreparationFixture()
    val calls = mutableListOf<SignHashRequestParameters>()
    var callback: QesQtspSigner = { catching { response } }

    fun holder(agent: Holder = HolderAgent(EphemeralKeyWithoutCert())): OpenId4VpHolder = OpenId4VpHolder(
        holder = agent,
        relyingPartyTrust = preparation.trust,
        qesDocumentRetriever = preparation.retriever,
        qesDtbsrPreparer = preparation.preparer,
    )

    suspend fun credential(
        validFrom: Instant = Clock.System.now(),
        key: EphemeralKeyWithoutCert = EphemeralKeyWithoutCert(),
        algorithm: SigningAlgorithm = signingAlgorithm,
    ): QesSigningCredential {
        val signingKey = TestCertificateAuthority().issue(key = key, validFrom = validFrom, extensions = listOf(X509CertificateExtension(
            oid = ObjectIdentifier("2.5.29.32"),
            value = Asn1EncapsulatingOctetString(listOf(Asn1.Sequence {
                +Asn1.Sequence { +ObjectIdentifier(policyOid) }
            })),
        )))
        val certificate = signingKey.getCertificate()!!
        return QesSigningCredential(credentialId = "provider-credential", credentialInfo = CredentialInfo(
            credentialID = "provider-credential",
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            keyParameters = KeyParameters(KeyParameters.KeyStatusOptions.ENABLED, setOf(algorithm.signAlgo),
                (key.publicKey as? CryptoPublicKey.RSA)?.bits?.number ?: 256U,
                (key.publicKey as? CryptoPublicKey.EC)?.curve?.oid),
            certParameters = CertificateParameters(status = CertificateParameters.CertStatus.VALID, certificates = listOf(certificate)),
            multisign = 1U,
        ), signHash = { request -> calls += request; callback(request) })
    }

    suspend fun prepare(
        transactions: List<TransactionData> = listOf(preparation.transaction),
        query: DCQLQuery = preparation.parameters.dcqlQuery!!,
    ): AuthorizationResponsePreparationState = holder().startAuthorizationResponsePreparation(preparation.sign(
        preparation.parameters.copy(dcqlQuery = query, transactionData = transactions.map { it.toBase64UrlJsonString() }),
    )).getOrThrow()

    suspend fun execute(state: AuthorizationResponsePreparationState, credential: QesSigningCredential): KmmResult<QesSigningResult> =
        holder().executeQesSigning(state, emptyMap(), mapOf(certificateId to credential), state.preparedQesDocuments.map {
            defaultChoice.copy(transactionIndex = it.transactionIndex, signatureRequestIndex = it.signatureRequestIndex)
        })

    suspend fun ordinarySubmissions(state: AuthorizationResponsePreparationState, agent: Holder):
            Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>> {
        val ordinary = state.request.parameters.dcqlQuery!!.credentials.filter { it !is DCQLX509CredentialQuery }
        return (agent.matchPresentationRequestAgainstCredentialStore(CredentialPresentationRequest.DCQLRequest(
            DCQLQuery(DCQLCredentialQueryList(ordinary.toNonEmptyList()))
        )).getOrThrow() as DCQLMatchingResult).matchingResult.credentialQueryMatches
    }
}
