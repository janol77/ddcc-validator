package org.who.ddccverifier

import ca.uhn.fhir.context.FhirContext
import org.hl7.fhir.r4.model.Bundle
import org.junit.Test
import org.opencds.cqf.cql.engine.execution.CqlLibraryReader
import org.cqframework.cql.cql2elm.CqlTranslator
import java.io.File
import org.cqframework.cql.cql2elm.LibraryManager
import org.cqframework.cql.cql2elm.ModelManager
import org.fhir.ucum.UcumEssenceService

import java.io.StringReader
import java.lang.IllegalArgumentException
import java.net.URLDecoder
import org.cqframework.cql.cql2elm.FhirLibrarySourceProvider
import org.opencds.cqf.cql.engine.execution.Context

import ca.uhn.fhir.context.FhirVersionEnum
import org.junit.Assert.*
import org.opencds.cqf.cql.engine.fhir.model.R4FhirModelResolver
import org.opencds.cqf.cql.evaluator.engine.retrieve.BundleRetrieveProvider
import org.opencds.cqf.cql.engine.data.CompositeDataProvider
import org.hl7.elm.r1.VersionedIdentifier
import org.hl7.fhir.instance.model.api.IBaseBundle
import org.hl7.fhir.r4.model.Composition
import org.hl7.fhir.r4.model.Immunization
import org.hl7.fhir.r4.model.Resource
import org.opencds.cqf.cql.engine.data.DataProvider
import org.opencds.cqf.cql.engine.execution.InMemoryLibraryLoader
import org.opencds.cqf.cql.engine.execution.LibraryLoader

class CQLTest {

    private fun open(assetName: String): String {
        return javaClass.classLoader?.getResourceAsStream(assetName)?.bufferedReader()
            .use { bufferReader -> bufferReader?.readText() } ?: ""
    }

    private val fhirContext = FhirContext.forCached(FhirVersionEnum.R4)
    private val jSONParser = fhirContext.newJsonParser()

    private val modelManager = ModelManager()
    private val libraryManager = LibraryManager(modelManager).apply {
        librarySourceLoader.registerProvider(FhirLibrarySourceProvider())
    }
    private val ucumService = UcumEssenceService(UcumEssenceService::class.java.getResourceAsStream("/ucum-essence.xml"))

    /**
     * Translate CQL to XML and loads the XML as a Library
     */
    private fun loadRules(cqlText: String): org.cqframework.cql.elm.execution.Library? {
        if (cqlText.startsWith("<?xml", true))
            return CqlLibraryReader.read(StringReader(cqlText))

        val translator = CqlTranslator.fromText(cqlText, modelManager, libraryManager, ucumService)
        if (translator.errors.size > 0) {
            System.err.println("Translation failed due to errors:")
            val errors: ArrayList<String> = ArrayList()
            for (error in translator.errors) {
                val tb = error.locator
                val lines = if (tb == null) "[n/a]" else String.format("[%d:%d, %d:%d]",
                    tb.startLine, tb.startChar, tb.endLine, tb.endChar)
                System.err.printf("%s %s%n", lines, error.message)
                errors.add(lines + error.message)
            }
            throw IllegalArgumentException(errors.toString())
        }
        assertEquals(0, translator.errors.size)
        return CqlLibraryReader.read(StringReader(translator.toXml()))
    }

    private fun loadDependencyLibraries(): LibraryLoader {
        val fhirHelperSource = libraryManager.librarySourceLoader.getLibrarySource(VersionedIdentifier().withId("FHIRHelpers").withVersion("4.0.0"))
        val translator = CqlTranslator.fromStream(fhirHelperSource, modelManager, libraryManager, ucumService)
        val fhirHelpers = CqlLibraryReader.read(StringReader(translator.toXml()))

        return InMemoryLibraryLoader(arrayListOf(fhirHelpers))
    }

    private fun loadDataProvider(assetBundle: IBaseBundle): DataProvider {
        val bundleRetrieveProvider = BundleRetrieveProvider(fhirContext, assetBundle)
        val r4ModelResolver = R4FhirModelResolver()
        return CompositeDataProvider(r4ModelResolver, bundleRetrieveProvider)
    }

    @Test
    fun evaluateHypertensivePatientCQL() {
        val assetBundle = jSONParser.parseResource(open("LibraryTestPatient.json")) as Bundle
        assertEquals("48d1906f-82df-44d2-9d26-284045504ba9", assetBundle.id)

        val cqlLibrary = loadRules(open("LibraryTestRules.cql"))

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(assetBundle))

        assertEquals(true, context.resolveExpressionRef("AgeRange-548").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("Essential hypertension (disorder)").evaluate(context))
        assertEquals(false, context.resolveExpressionRef("Malignant hypertensive chronic kidney disease (disorder)").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("MeetsInclusionCriteria").evaluate(context))
        assertEquals(false, context.resolveExpressionRef("MeetsExclusionCriteria").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("InPopulation").evaluate(context))
        assertEquals("", context.resolveExpressionRef("Recommendation").evaluate(context))
        assertNull(context.resolveExpressionRef("Rationale").evaluate(context))
        assertNull(context.resolveExpressionRef("Errors").evaluate(context))
    }

    @Test
    fun evaluateHypertensivePatientXML() {
        val assetBundle = jSONParser.parseResource(open("LibraryTestPatient.json")) as Bundle
        assertEquals("48d1906f-82df-44d2-9d26-284045504ba9", assetBundle.id)

        val cqlLibrary = loadRules(open("LibraryTestRules.xml"))

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(assetBundle))

        assertEquals(true, context.resolveExpressionRef("AgeRange-548").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("Essential hypertension (disorder)").evaluate(context))
        assertEquals(false, context.resolveExpressionRef("Malignant hypertensive chronic kidney disease (disorder)").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("MeetsInclusionCriteria").evaluate(context))
        assertEquals(false, context.resolveExpressionRef("MeetsExclusionCriteria").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("InPopulation").evaluate(context))
        assertEquals("", context.resolveExpressionRef("Recommendation").evaluate(context))
        assertNull(context.resolveExpressionRef("Rationale").evaluate(context))
        assertNull(context.resolveExpressionRef("Errors").evaluate(context))
    }

    @Test
    fun evaluateQR1DDCCCQL() {
        val asset = jSONParser.parseResource(open("QR1FHIRComposition.json")) as Composition
        assertEquals("Composition/US111222333444555666", asset.id)

        val cqlLibrary = loadRules(open("DDCCPass.cql"))
        val bundle = Bundle()
        asset.contained.forEach {
            bundle.addEntry().setResource(it)
        }

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(bundle))

        assertEquals(false, context.resolveExpressionRef("CompletedImmunization").evaluate(context))
        assertEquals(null, context.resolveExpressionRef("GetFinalDose").evaluate(context))
    }

    @Test
    fun evaluateQR1DDCCXML() {
        val asset = jSONParser.parseResource(open("QR1FHIRComposition.json")) as Composition
        assertEquals("Composition/US111222333444555666", asset.id)

        val cqlLibrary = loadRules(open("DDCCPass.xml"))
        val bundle = Bundle()
        asset.contained.forEach {
            bundle.addEntry().setResource(it)
        }

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(bundle))

        assertEquals(false, context.resolveExpressionRef("CompletedImmunization").evaluate(context))
        assertEquals(null, context.resolveExpressionRef("GetFinalDose").evaluate(context))
    }

    @Test
    fun evaluateQR2DDCCCQL() {
        val asset = jSONParser.parseResource(open("QR2FHIRComposition.json")) as Composition
        assertEquals("Composition/111000111", asset.id)

        val cqlLibrary = loadRules(open("DDCCPass.cql"))
        val bundle = Bundle()
        asset.contained.forEach {
            bundle.addEntry().setResource(it)
        }

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(bundle))

        assertNotNull(context.resolveExpressionRef("GetSingleDose").evaluate(context))
        assertNull( context.resolveExpressionRef("GetFinalDose").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("CompletedImmunization").evaluate(context))
    }

    @Test
    fun evaluateQR2DDCCXML() {
        val asset = jSONParser.parseResource(open("QR2FHIRComposition.json")) as Composition
        assertEquals("Composition/111000111", asset.id)

        val cqlLibrary = loadRules(open("DDCCPass.xml"))
        val bundle = Bundle()
        asset.contained.forEach {
            bundle.addEntry().setResource(it)
        }

        val context = Context(cqlLibrary)
        context.registerLibraryLoader(loadDependencyLibraries())
        context.registerDataProvider("http://hl7.org/fhir", loadDataProvider(bundle))

        assertNotNull(context.resolveExpressionRef("GetSingleDose").evaluate(context))
        assertNull(context.resolveExpressionRef("GetFinalDose").evaluate(context))
        assertEquals(true, context.resolveExpressionRef("CompletedImmunization").evaluate(context))
    }
}