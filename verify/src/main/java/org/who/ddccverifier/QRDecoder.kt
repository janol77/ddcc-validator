package org.who.ddccverifier

import org.hl7.fhir.r4.model.Bundle
import org.hl7.fhir.r4.model.Composition
import org.who.ddccverifier.trust.TrustRegistry
import org.who.ddccverifier.verify.divoc.DivocVerifier
import org.who.ddccverifier.verify.hcert.HCertVerifier
import org.who.ddccverifier.verify.icao.IcaoVerifier
import org.who.ddccverifier.verify.shc.ShcVerifier

/**
 * Finds the right processor for the QR Content and returns the DDCC Composition of that Content.
 */
class QRDecoder(private val registry: TrustRegistry) {
    enum class Status {
        NOT_FOUND, // QR not found in the Image
        NOT_SUPPORTED, // QR Standard not supported by this algorithm
        INVALID_ENCODING, // could not decode Base45 for DCC, Base10 for SHC,
        INVALID_COMPRESSION, // could not decompress the byte array
        INVALID_SIGNING_FORMAT, // invalid COSE, JOSE, W3C VC Payload
        KID_NOT_INCLUDED, // unable to resolve the issuer ID
        ISSUER_NOT_TRUSTED, // issuer is not found in the registry
        TERMINATED_KEYS, // issuer was terminated by the registry
        EXPIRED_KEYS, // keys expired
        REVOKED_KEYS, // keys were revoked by the issuer
        INVALID_SIGNATURE, // signature doesn't match
        VERIFIED,  // Verified content.
    }

    data class VerificationResult (
        var status: Status,
        var contents: Bundle?, // the DDCC Composition
        var issuer: TrustRegistry.TrustedEntity?,
        var qr: String,
        var unpacked: String?,
        var country: String? = null,
    ) {
        fun composition() = contents?.entry?.filter { it.resource is Composition }?.firstOrNull()?.resource as Composition?
    }

    fun decode(qrPayload : String): VerificationResult {
        if (qrPayload.uppercase().startsWith("HC1:")) {
            return HCertVerifier(registry).unpackAndVerify(qrPayload)
        }
        if (qrPayload.uppercase().startsWith("SHC:")) {
            return ShcVerifier(registry).unpackAndVerify(qrPayload)
        }
        if (qrPayload.uppercase().startsWith("B64:") || qrPayload.uppercase().startsWith("PK")) {
            return DivocVerifier(registry).unpackAndVerify(qrPayload)
        }
        if (qrPayload.uppercase().contains("ICAO")) {
            return IcaoVerifier(registry).unpackAndVerify(qrPayload)
        }

        return VerificationResult(Status.NOT_SUPPORTED, null, null, qrPayload, null)
    }
}