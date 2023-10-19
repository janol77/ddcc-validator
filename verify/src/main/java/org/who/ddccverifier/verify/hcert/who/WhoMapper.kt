package org.who.ddccverifier.verify.hcert.who

import org.hl7.fhir.r4.model.Bundle
import org.who.ddccverifier.verify.BaseMapper

/**
 * Translates a DDCC QR CBOR object into FHIR Objects
 */
class WhoMapper: BaseMapper() {
    fun run(who: WHOLogicalModel): Bundle {
        return super.run(
            who,
            "WHOtoDDCC.map"
        )
    }
}