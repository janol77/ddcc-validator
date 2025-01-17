package org.who.ddccverifier.trust.didweb

import org.junit.Assert.assertNotNull
import org.junit.BeforeClass
import org.junit.Test
import org.who.ddccverifier.trust.TrustRegistry

class DDCCTrustRegistryTest {
    companion object {
        var registry = DDCCTrustRegistry()
        @BeforeClass @JvmStatic fun setup() {
            registry.init(DDCCTrustRegistry.PRODUCTION_REGISTRY, DDCCTrustRegistry.ACCEPTANCE_REGISTRY)
        }
    }

    @Test
    fun loadEntity() {
        val t = registry.resolve(TrustRegistry.Framework.DIVOC, "india")
        assertNotNull(t)
    }

    @Test
    fun testSHCWA() {
        val t = registry.resolve(TrustRegistry.Framework.SHC, "https://waverify.doh.wa.gov/creds#n0S0H6_mbA93e3pEu-a67qoiF4CAWYsOGoWo6TLHUzQ")
        assertNotNull(t)
    }

    @Test
    fun testDCCItalyAcceptance() {
        val t = registry.resolve(TrustRegistry.Framework.DCC, "OTAXaM3aBRM=")
        assertNotNull(t)
    }

    @Test
    fun testSCHSenegal() {
        val t = registry.resolve(TrustRegistry.Framework.SHC, "https://senegal.tbi.ohms.oracle.com#VEccqX9LvPZJXqv11staEs0qPN2OR9bMS_PXEAZODXg")
        assertNotNull(t)
    }

    @Test
    fun testICAOAustrala() {
        val t = registry.resolve(TrustRegistry.Framework.ICAO, "AU#NhfB5/VnlXEuN3VwjlWDMYbpOA4=")
        assertNotNull(t)
    }

    @Test
    fun testICAOJapan() {
        val t = registry.resolve(TrustRegistry.Framework.ICAO, "JP#arTykoK9lkf2/yoC95RNdJ6XhGM=")
        assertNotNull(t)
    }

    @Test
    fun testDDCCLuxemburg() {
        // did:web:tng-cdn-dev.who.int:trustlist:lux#40wemvsu28E%3D
        val t = registry.resolve(TrustRegistry.Framework.DCC, "lux#40wemvsu28E=")
        assertNotNull(t)
    }
}

