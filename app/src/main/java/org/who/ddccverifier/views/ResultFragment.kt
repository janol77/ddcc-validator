package org.who.ddccverifier.views

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.upokecenter.cbor.CBORObject
import org.who.ddccverifier.R
import org.who.ddccverifier.databinding.FragmentResultBinding
import org.who.ddccverifier.services.DDCCFormatter
import org.who.ddccverifier.services.DDCCVerifier

/**
 * Displays a Verifiable Credential after being Scanned by the QRScan Fragment
 */
class ResultFragment : Fragment() {
    private var _binding: FragmentResultBinding? = null
    private val args: ResultFragmentArgs by navArgs()

    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater, container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResultBinding.inflate(inflater, container, false)
        return binding.root
    }

    private fun setTextView(view: TextView, text: String?) {
        if (text != null && !text.isEmpty()) {
            view.text = text
            view.visibility = TextView.VISIBLE
        } else
            view.visibility = TextView.GONE
    }

    data class ResultCard(
        val cardTitle: String?,
        val personName: String?,
        val personDetails: String?,
        val dose: String?,
        val doseDate: String?,
        val nextDose: String?,
        val vaccineValid: String?,
        val vaccineAgainst: String?,
        val vaccineType: String?,
        val vaccineInfo: String?,
        val vaccineInfo2: String?,
        val location: String?,
        val hcid: String?,
        val pha: String?,
        val identifier: String?,
        val hw: String?,
        val validUntil: String?
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        if (args.qr != null) {
            val DDCC = DDCCVerifier().unpackAndVerify(args.qr!!);
            if (DDCC.contents != null) {
                val card : ResultCard = DDCCFormatter().run(DDCC.contents!!);
                setTextView(binding.tvResultScanDate, card.cardTitle)
                setTextView(binding.tvResultName, card.personName)
                setTextView(binding.tvResultPersonDetails, card.personDetails)
                setTextView(binding.tvResultValidUntil, card.validUntil)
                setTextView(binding.tvResultDoseTitle, card.dose)
                setTextView(binding.tvResultDoseDate, card.doseDate)
                setTextView(binding.tvResultNextDose, card.nextDose)
                setTextView(binding.tvResultVaccineValid, card.vaccineValid)
                setTextView(binding.tvResultVaccineType, card.vaccineType)
                setTextView(binding.tvResultVaccineInfo, card.vaccineInfo)
                setTextView(binding.tvResultVaccineInfo2, card.vaccineInfo2)
                setTextView(binding.tvResultCentre, card.location)
                setTextView(binding.tvResultHcid, card.hcid)
                setTextView(binding.tvResultPha, card.pha)
                setTextView(binding.tvResultIdentifier, card.identifier)
                setTextView(binding.tvResultHw, card.hw)
            }
        }

        binding.btResultClose.setOnClickListener {
            findNavController().navigate(R.id.action_ResultFragment_to_HomeFragment)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}