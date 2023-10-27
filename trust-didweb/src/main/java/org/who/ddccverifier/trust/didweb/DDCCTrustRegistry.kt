package org.who.ddccverifier.trust.didweb

import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import foundation.identity.did.jsonld.DIDKeywords
import foundation.identity.jsonld.JsonLDUtils
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
import jakarta.json.JsonObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.who.ddccverifier.trust.TrustRegistry
import java.net.URI
import java.net.URLEncoder
import java.security.PublicKey
import java.security.Security
import java.text.ParseException
import java.util.*
import java.util.function.Function
import kotlin.system.measureTimeMillis
import kotlin.time.ExperimentalTime
import kotlin.time.measureTimedValue

operator fun <T> List<T>.component6() = this[5]
operator fun <T> List<T>.component7() = this[6]
operator fun <T> List<T>.component8() = this[7]

/**
 * Resolve Keys for Verifiers from PathCheck's CSV file
 */
class DDCCTrustRegistry : TrustRegistry {
    companion object {
        const val PROD_KEY_ID = "did:web:tng-cdn-uat.who.int:trustlist"
        const val TEST_KEY_ID = "did:web:tng-cdn-dev.who.int:trustlist"

        const val PROD_DID = "did:web:tng-cdn-uat.who.int:trustlist"  //this is UAT not PROD!!!
        const val TEST_DID = "did:web:tng-cdn-dev.who.int:trustlist"

        val PRODUCTION_REGISTRY = TrustRegistry.RegistryEntity(TrustRegistry.Scope.PRODUCTION, URI(PROD_DID), null)
        val ACCEPTANCE_REGISTRY =  TrustRegistry.RegistryEntity(TrustRegistry.Scope.ACCEPTANCE_TEST, URI(TEST_DID), null)
    }

    // Builds a map of all Frameworks
    private val registry = mutableMapOf<URI, TrustRegistry.TrustedEntity>()

    private fun wrapPem(pemB64: String): String {
        return "-----BEGIN PUBLIC KEY-----\n$pemB64\n-----END PUBLIC KEY-----"
    }

    private fun buildPublicKey(verif: VerificationMethod): PublicKey? {
        if (verif.publicKeyJwk != null) {
            try {
                val key = JWK.parse(verif.publicKeyJwk)
                if (key is AsymmetricJWK) {
                    return key.toPublicKey()
                }
            } catch (e: ParseException) {
                // tries to reassemble the public key from the first certificate
                if (verif.publicKeyJwk.containsKey("x5c")) {
                    val certPem = (verif.publicKeyJwk.get("x5c") as List<*>).firstOrNull()
                    return KeyUtils.certificatePublicKeyFromPEM(
                        "-----BEGIN CERTIFICATE-----\n$certPem\n-----END CERTIFICATE-----"
                    )
                } else {
                    throw e
                }
            }
        }

        if (verif.publicKeyBase64 != null) {
            val key = wrapPem(verif.publicKeyBase64)
            return KeyUtils.publicKeyFromPEM(key)
        }

        if (verif.publicKeyBase58 != null) {
            return KeyUtils.eddsaFromBytes(Base58.decode(verif.publicKeyBase58))
        }

        if (verif.publicKeyMultibase != null) {
            return KeyUtils.eddsaFromBytes(Multibase.decode(verif.publicKeyMultibase))
        }

        println("unable to load key ${verif.id}")

        return null
    }

    fun DIDDocument.parseVerificationMethods(): List<VerificationMethod> {
        val jsonArray = JsonLDUtils.jsonLdGetJsonArray(getJsonObject(), DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD)
        return jsonArray.mapNotNull {
            if (it is Map<*, *>) {
                val method = VerificationMethod.fromJsonObject(it as Map<String, Any>)
                if (method is VerificationMethod) {
                    method
                } else {
                    null
                }
            } else {
                null
            }
        }
    }

    @OptIn(ExperimentalTime::class)
    fun load(registryURL: TrustRegistry.RegistryEntity) {
        try {
            val (didDocumentResolution, elapsedServerDownload) = measureTimedValue {
                DIDWebResolver().resolve(registryURL.resolvableURI)
            }
            println("TIME: Trust Downloaded in $elapsedServerDownload from ${registryURL.resolvableURI}")

            val elapsed = measureTimeMillis {
                didDocumentResolution?.didDocument?.parseVerificationMethods()?.forEach {
                    try {
                        val key = buildPublicKey(it)
                        if (key != null)
                            registry.put(it.id,
                                TrustRegistry.TrustedEntity(
                                    mapOf("en" to it.id.toString()),
                                    "",
                                    TrustRegistry.Status.CURRENT,
                                    registryURL.scope,
                                    null,
                                    null,
                                    key
                                )
                            )

                        println("Loaded: ${it.id}")
                    } catch(t: Throwable) {
                        println("Exception while loading kid: ${it.id}")
                        t.printStackTrace()
                    }
                }
            }

            println("TIME: Trust Parsed and Loaded in ${elapsed}ms")

        } catch(t: Throwable) {
            println("Exception while loading registry from github")
            t.printStackTrace()
        }
    }

    override fun init(vararg customRegistries: TrustRegistry.RegistryEntity) {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())

        registry.clear()

        customRegistries.forEach {
            load(it)
        }
    }

    override fun init() {
        println("DID:WEB: Initializing")
        init(PRODUCTION_REGISTRY, ACCEPTANCE_REGISTRY)
    }

    override fun resolve(framework: TrustRegistry.Framework, kid: String): TrustRegistry.TrustedEntity? {
        if (kid.contains("#")) {
            val parts = kid.split("#")
            val encController = URLEncoder.encode(parts[0],"UTF-8")
            val encKid = URLEncoder.encode(parts[1],"UTF-8")
            println("DID:WEB: Resolving $kid -> $PROD_KEY_ID:$encController#$encKid")
            return registry[URI.create("$PROD_KEY_ID:$encController#$encKid")]
                ?: registry[URI.create("$TEST_KEY_ID:$encController#$encKid")]
        } else {
            val encKid = URLEncoder.encode(kid,"UTF-8")
            println("DID:WEB: Resolving $kid -> $PROD_KEY_ID:$encKid#$encKid")
            // hardcode de country for testing XCL, remove after fix the generator
            return registry[URI.create("$PROD_KEY_ID:$encKid#$encKid")]
                ?: registry[URI.create("$TEST_KEY_ID:xcl#$encKid")]
        }
    }
}
