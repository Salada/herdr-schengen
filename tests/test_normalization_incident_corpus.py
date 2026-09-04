"""Executable contract for normalization incidents and adversarial wraps."""

import json
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from adapters.capture_evaluator import evaluate_capture_pair


CORPUS = Path(__file__).parent / "fixtures" / "normalization_incidents.json"


class TestNormalizationIncidentCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(CORPUS.read_text(encoding="utf-8"))

    def test_case_ids_are_unique_and_screenshots_are_covered(self):
        ids = [case["id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            {f"screenshot-{number}" for number in range(1, 8)},
            {"-".join(case_id.split("-")[:2]) for case_id in ids if case_id.startswith("screenshot-")},
        )

    def test_corpus_contract(self):
        for case in self.cases:
            with self.subTest(case=case["id"]):
                for field in (
                    "raw_input",
                    "canonical_input",
                    "normalization_provenance",
                    "expected_layer",
                    "expected_outcome",
                ):
                    self.assertIn(field, case)

                if case["expected_outcome"] == "non-adjudicating":
                    self.assertTrue(case["canonical_input"].startswith("question"))
                    self.assertEqual(case["expected_layer"], "QUESTION")
                    continue

                safe, _reason, layer, taxonomy = evaluate_capture_pair(
                    case["raw_input"],
                    case["canonical_input"],
                    case["normalization_provenance"],
                    reasoning_effort="none",
                )
                outcome = "approve" if safe else ("block" if taxonomy["consequence"] != "NONE" else "defer")
                self.assertEqual(layer.value, case["expected_layer"])
                self.assertEqual(outcome, case["expected_outcome"])
                self.assertEqual(taxonomy["capture_source"], case["normalization_provenance"])
                self.assertTrue(taxonomy["raw_capture_evaluated"])


if __name__ == "__main__":
    unittest.main()
