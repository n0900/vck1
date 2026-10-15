package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.AccessControlMethod
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.toBase64UrlJsonString
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.rqes.QesDocumentPreparation
import at.asitplus.wallet.lib.rqes.QesDocumentRetriever
import at.asitplus.wallet.lib.rqes.QesDtbsrPreparer
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.CancellationException

val OpenId4VpQesDocumentPreparationTest by matrixSuite {
    "prepares embedded documents with complete signing parameters and preserves source bytes" {
        val fixture = QesPreparationFixture()
        val bytes = byteArrayOf(0, -1, 2, -128)
        val context = byteArrayOf(8, 9)
        val request = fixture.transaction.signatureRequests.single().copy(
            document = DocumentData(label = "Contract", document = bytes),
            adesParameters = AdesParameters(signatureFormat = SignatureFormat.PADES),
            signingAlgorithm = SigningAlgorithm(X509SignatureAlgorithm.ES384.oid),
            responseUri = "https://rp.example/signed",
        )
        var calls = 0
        val state = fixture.prepareDocuments(
            transactions = listOf(fixture.transaction.copy(signatureRequests = listOf(request))),
            retriever = null,
            preparer = { actualRequest, actualBytes ->
                catching {
                    calls++
                    actualRequest shouldBe request
                    actualBytes.contentEquals(bytes) shouldBe true
                    val hash = Hash(Digest.SHA384.digest(actualBytes), Digest.SHA384.oid)
                    actualBytes.fill(0) // A format library may prepare the bytes in place.
                    QesDocumentPreparation(hash, context)
                }
            },
        ).getOrThrow()
        calls shouldBe 1
        state.preparedQesDocuments.single().apply {
            transactionIndex shouldBe 0
            signatureRequestIndex shouldBe 0
            document.contentEquals(bytes) shouldBe true
            integrityVerified shouldBe false
            preparation shouldBe QesDocumentPreparation(Hash(Digest.SHA384.digest(bytes), Digest.SHA384.oid), context)
        }
        state.request.parameters.transactionDataDecoded shouldBe listOf(
            fixture.transaction.copy(
                signatureRequests = listOf(
                    request
                )
            )
        )
        val restored = joseCompliantSerializer.decodeFromString<AuthorizationResponsePreparationState>(
            joseCompliantSerializer.encodeToString(state),
        )
        restored shouldBe state
        restored.preparedQesDocuments.hashCode() shouldBe state.preparedQesDocuments.hashCode()
    }

    listOf(Digest.SHA256, Digest.SHA384, Digest.SHA512)
        .asData(nameFn = { "verifies $it source integrity independently of the DTBSR" }) test { digest ->
        val fixture = QesPreparationFixture()
        val bytes = byteArrayOf(-1, 0, 1, 2)
        val reference = DocumentReference(
            label = "Contract", href = "https://rp.example/contract.pdf",
            access = AccessControlMethod.OTP("12345"),
            checksum = Hash(digest.digest(bytes), digest.oid),
            circumstantialData = byteArrayOf(7),
        )
        val request = fixture.transaction.signatureRequests.single().copy(document = reference)
        var fetched = 0
        var prepared = 0
        val result = fixture.prepareDocuments(
            transactions = listOf(fixture.transaction.copy(signatureRequests = listOf(request))),
            retriever = { actual ->
                catching {
                    actual shouldBe reference
                    fetched++
                    bytes
                }
            },
            preparer = { actual, resolved ->
                catching {
                    fetched shouldBe 1
                    actual shouldBe request
                    resolved.contentEquals(bytes) shouldBe true
                    prepared++
                    QesDocumentPreparation(Hash(Digest.SHA256.digest(byteArrayOf(99)), Digest.SHA256.oid))
                }
            },
        ).getOrThrow().preparedQesDocuments.single()
        prepared shouldBe 1
        result.integrityVerified shouldBe true
        result.preparation.dtbsr shouldBe Hash(Digest.SHA256.digest(byteArrayOf(99)), Digest.SHA256.oid)
    }

    listOf("https://rp.example/contract.pdf", "data:application/pdf;base64,AQID")
        .asData(nameFn = { "delegates reference retrieval without checksum: $it" }) test { href ->
        val fixture = QesPreparationFixture()
        val reference = DocumentReference(href = href)
        var fetched = 0
        val state = fixture.prepareDocuments(
            transactions = listOf(
                fixture.transaction.copy(
                    signatureRequests = listOf(
                        fixture.transaction.signatureRequests.single().copy(document = reference),
                    )
                )
            ),
            retriever = { actual ->
                catching {
                    actual shouldBe reference
                    fetched++
                    byteArrayOf(1, 2, 3)
                }
            },
        ).getOrThrow()
        fetched shouldBe 1
        state.preparedQesDocuments.single().integrityVerified shouldBe false
    }

    listOf("mismatch", "weak algorithm")
        .asData(nameFn = { "rejects checksum $it before DTBSR preparation" }) test { invalid ->
        val fixture = QesPreparationFixture()
        val digest = if (invalid == "weak algorithm") Digest.SHA1 else Digest.SHA256
        val reference = DocumentReference(
            href = "https://rp.example/contract.pdf",
            checksum = Hash(digest.digest(byteArrayOf(1, 2, 3)), digest.oid),
        )
        var prepared = 0
        fixture.prepareDocuments(
            transactions = listOf(
                fixture.transaction.copy(
                    signatureRequests = listOf(
                        fixture.transaction.signatureRequests.single().copy(document = reference),
                    )
                )
            ),
            retriever = { catching { if (invalid == "mismatch") byteArrayOf(4, 5) else byteArrayOf(1, 2, 3) } },
            preparer = { request, bytes -> prepared++; fixture.preparer(request, bytes) },
        ).exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
        prepared shouldBe 0
    }

    listOf("retriever", "preparer")
        .asData(nameFn = { "requires a configured QES $it" }) test { missing ->
        val fixture = QesPreparationFixture()
        var fetched = 0
        fixture.prepareDocuments(
            retriever = if (missing == "retriever") null else { _ -> fetched++; catching { byteArrayOf(1) } },
            preparer = if (missing == "preparer") null else fixture.preparer,
        ).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        fetched shouldBe 0
    }

    listOf("retriever result", "retriever throw", "preparer result", "preparer throw")
        .asData(nameFn = { "preserves the cause of a failed $it" }) test { failure ->
        val fixture = QesPreparationFixture()
        val cause = IllegalStateException("service failed")
        var prepared = 0
        val result = fixture.prepareDocuments(
            retriever = { reference ->
                when (failure) {
                    "retriever result" -> catching { throw cause }
                    "retriever throw" -> throw cause
                    else -> fixture.retriever(reference)
                }
            },
            preparer = { _, _ ->
                prepared++
                if (failure == "preparer throw") throw cause
                catching { throw cause }
            },
        )
        result.exceptionOrNull().shouldBeInstanceOf<InvalidRequest>().cause shouldBe cause
        prepared shouldBe if (failure.startsWith("preparer")) 1 else 0
    }

    listOf("retriever", "preparer")
        .asData(nameFn = { "propagates cancellation from the $it" }) test { service ->
        val fixture = QesPreparationFixture()
        val cancellation = CancellationException("cancelled")
        shouldThrow<CancellationException> {
            fixture.prepareDocuments(
                retriever = { reference ->
                    if (service == "retriever") throw cancellation else fixture.retriever(
                        reference
                    )
                },
                preparer = { _, _ -> throw cancellation },
            )
        } shouldBe cancellation
    }

    "rejects an invalid DTBSR result" {
        val fixture = QesPreparationFixture()
        fixture.prepareDocuments(preparer = { _, _ ->
            catching {
                QesDocumentPreparation(Hash(byteArrayOf(1), Digest.SHA256.oid))
            }
        }).exceptionOrNull().shouldBeInstanceOf<InvalidTransactionData>()
    }

    "rejects unauthenticated requests before invoking either service" {
        val fixture = QesPreparationFixture()
        var calls = 0
        OpenId4VpHolder(
            relyingPartyTrust = emptySet(),
            qesDocumentRetriever = { reference -> calls++; fixture.retriever(reference) },
            qesDtbsrPreparer = { request, bytes -> calls++; fixture.preparer(request, bytes) },
        ).startAuthorizationResponsePreparation(fixture.sign()).exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        calls shouldBe 0
    }

    listOf("ordinary presentation", "QES approval")
        .asData(nameFn = { "does not prepare documents for an $it" }) test { profile ->
        val fixture = QesPreparationFixture()
        var calls = 0
        val request = fixture.parameters.copy(
            dcqlQuery = joseCompliantSerializer.decodeFromString<DCQLQuery>(
                """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]}}]}""",
            ),
            transactionData = if (profile == "ordinary presentation") null else listOf(
                joseCompliantSerializer.decodeFromString<TransactionData>(
                    """{"type":"https://cloudsignatureconsortium.org/2025/qes-approval",
                        "credential_ids":["pid"],"numSignatures":1,"signatureQualifier":"eu_eidas_qes",
                        "documentDigests":[{"hash":"AQID"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"}""",
                ).toBase64UrlJsonString(),
            ),
        )
        val state = OpenId4VpHolder(
            qesDocumentRetriever = { reference -> calls++; fixture.retriever(reference) },
            qesDtbsrPreparer = { signatureRequest, bytes -> calls++; fixture.preparer(signatureRequest, bytes) },
        ).startAuthorizationResponsePreparation(fixture.sign(request)).getOrThrow()
        calls shouldBe 0
        state.preparedQesDocuments shouldBe emptyList()
    }

    "retains document order and original indices across mixed transactions" {
        val fixture = QesPreparationFixture()
        val approval = joseCompliantSerializer.decodeFromString<TransactionData>(
            """{"type":"https://cloudsignatureconsortium.org/2025/qes-approval",
                "credential_ids":["certificate"],"numSignatures":1,"signatureQualifier":"eu_eidas_qes",
                "documentDigests":[{"hash":"AQID"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"}""",
        )
        val requests = listOf(1, 2).map { value ->
            fixture.transaction.signatureRequests.single().copy(
                document = DocumentData(document = byteArrayOf(value.toByte())),
            )
        }
        var calls = 0
        val state = fixture.prepareDocuments(
            transactions = listOf(
                approval,
                fixture.transaction.copy(signatureRequests = requests),
                fixture.transaction
            ),
            preparer = { request, bytes -> calls++; fixture.preparer(request, bytes) },
        ).getOrThrow()
        calls shouldBe 3
        state.preparedQesDocuments.map { it.transactionIndex to it.signatureRequestIndex } shouldBe
                listOf(1 to 0, 1 to 1, 2 to 0)
        state.preparedQesDocuments.map { it.document.toList() } shouldBe
                listOf(listOf<Byte>(1), listOf<Byte>(2), listOf<Byte>(1, 2, 3))
    }

    "fails the entire preparation when a later document fails" {
        val fixture = QesPreparationFixture()
        var calls = 0
        val cause = IllegalStateException("second document failed")
        val result = fixture.prepareDocuments(
            transactions = listOf(fixture.transaction.copy(signatureRequests = List(2) { fixture.transaction.signatureRequests.single() })),
            preparer = { request, bytes ->
                if (++calls == 2) throw cause
                fixture.preparer(request, bytes)
            },
        )
        calls shouldBe 2
        result.exceptionOrNull().shouldBeInstanceOf<InvalidRequest>().cause shouldBe cause
    }
}

private suspend fun QesPreparationFixture.prepareDocuments(
    transactions: List<TransactionData> = listOf(transaction),
    retriever: QesDocumentRetriever? = this.retriever,
    preparer: QesDtbsrPreparer? = this.preparer,
): KmmResult<AuthorizationResponsePreparationState> = OpenId4VpHolder(
    relyingPartyTrust = trust,
    qesDocumentRetriever = retriever,
    qesDtbsrPreparer = preparer,
).startAuthorizationResponsePreparation(sign(parameters.copy(transactionData = transactions.map { it.toBase64UrlJsonString() })))
