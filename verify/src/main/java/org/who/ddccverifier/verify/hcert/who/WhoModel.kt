package org.who.ddccverifier.verify.hcert.who

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.TreeNode
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.hl7.fhir.r4.model.*
import org.who.ddccverifier.verify.BaseModel
import org.who.ddccverifier.verify.shc.DecimalToDataTimeDeserializer
import kotlin.reflect.full.declaredMemberProperties


class WHO_CWT (
    @JsonProperty("1")
    val iss: StringType?,   // Issuer
    @JsonProperty("2")
    val sub: StringType?,   // Subject
    @JsonProperty("3")
    val aud: StringType?,   // Audience
    @JsonProperty("4")
    @JsonDeserialize(using = DecimalToDataTimeDeserializer::class)
    val exp: DateTimeType?, // expiration
    @JsonProperty("5")
    @JsonDeserialize(using = DecimalToDataTimeDeserializer::class)
    val nbf: DateTimeType?, // not before date
    @JsonProperty("6")
    @JsonDeserialize(using = DecimalToDataTimeDeserializer::class)
    val iat: DateTimeType?, // issued at date
    @JsonProperty("7")
    val id: StringType?,   // Audience
    @JsonProperty("-255")
    val data: WHOLogicalModel?,      // Certificate
): BaseModel()

// class WHO_HCERT(
//     @JsonProperty("1")
//     val cert: WHOLogicalModel?          // Cert
// ): BaseModel()
@JsonIgnoreProperties(ignoreUnknown = true)
class WHOLogicalModel (

    // val meta: Meta?,

    val name: StringType?,
    val birthDate: DateType?,
    val sex: CodeType?,
    val identifier: StringType?,

    // test
    // val test: TestResult?,

    // certificate
    val certificate: CertificateData?,
    // vaccination
    val vaccination: VaccinationData?,
): BaseModel()

class CertificateData (
    val hcid: StringType?,
    val issuer: IssuerData?,
    val period: PeriodData?,
    val version: StringType?,
): BaseModel()

class IssuerData (
    val identifier: StringType?,
): BaseModel()

class PeriodData (
    val start: DateTimeType?,
    val end: DateTimeType?,
): BaseModel()

class VaccinationData (
    val lot: StringType?,
    val date: DateTimeType?,
    val dose: PositiveIntType?,
    val brand: Coding?,
    val centre: StringType?,
    val country: Coding?,
    val disease: Coding?,
    val vaccine: Coding?,
    val maholder: Coding?,
    val nextDose: DateTimeType?,
    val validFrom: DateType?,
    val totalDoses: PositiveIntType?,
    @JsonDeserialize(using = CodingOrReferenceDeserializer::class)
    val manufacturer: Base?,
    val practitioner: StringType?
): BaseModel()

class TestResult (
    val pathogen: Coding?,
    val type: Coding?,
    val brand: Coding?,
    val manufacturer: Coding?,
    val origin: Coding?,
    val date: DateTimeType?,
    val result: Coding?,
    val centre: StringType?,
    val country: Coding?
): BaseModel()

class Meta (
    val notarisedOn: DateTimeType?,
    val reference: StringType?,
    val url: StringType?,
    val passportNumber: StringType?
): org.hl7.fhir.r4.model.Meta() {
    private val propertiesByHash = this::class.declaredMemberProperties.associateBy { it.name.hashCode() }

    override fun getProperty(hash: Int, name: String?, checkValid: Boolean): Array<Base?> {
        return propertiesByHash[hash]?.let {
            val prop = it.getter.call(this)
            if (prop == null) {
                emptyArray()
            } else if (prop is Base) {
                arrayOf(prop)
            } else if (prop is Collection<*>) {
                if (prop.isEmpty()) {
                    emptyArray()
                } else {
                    (prop as Collection<Base?>).toTypedArray()
                }
            } else {
                emptyArray()
            }
        } ?: super.getProperty(hash, name, checkValid)
    }
}

object CodingOrReferenceDeserializer: JsonDeserializer<Base>() {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): Base? {
        val token: TreeNode = p.readValueAsTree()

        return if (token.isValueNode) {
            Reference().apply {
                id = token.toString()
            }
        } else {
            return jacksonObjectMapper().readValue<Coding>(token.toString())
        }
    }
}