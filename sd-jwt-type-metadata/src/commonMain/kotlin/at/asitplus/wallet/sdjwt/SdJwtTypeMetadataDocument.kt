package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement

/**
 * Separation between the originally received json data and the decoded one allows for reserialization while preserving
 * integrity with vct#integrity and extends#integrity.
 */
@Serializable(with = SdJwtTypeMetadataDocument.Serializer::class)
data class SdJwtTypeMetadataDocument(
    val original: String,
    val definition: SdJwtTypeMetadataDefinition
) {
    class Serializer : KSerializer<SdJwtTypeMetadataDocument> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = Serializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING
            )

        override fun serialize(
            encoder: Encoder,
            value: SdJwtTypeMetadataDocument
        ) {
            encoder.encodeString(value.original)
        }

        override fun deserialize(decoder: Decoder): SdJwtTypeMetadataDocument {
            require(decoder is JsonDecoder) {
                "Expected decoder to be JsonDeocder, but got `$decoder`."
            }

            val jsonElement = decoder.decodeJsonElement()
            val decoded = decoder.json.decodeFromJsonElement(
                SdJwtTypeMetadataDefinition.serializer(),
                jsonElement
            )

            return SdJwtTypeMetadataDocument(
                // TODO: is this good enough to retain the original character sequence for integrity checks?
                original = jsonElement.toString(),
                definition = decoded
            )
        }
    }
}