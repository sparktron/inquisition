from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

import mitre
from models import (
    Finding,
    FindingCategory,
    ScanReport,
    Severity,
)


def _finding(category: FindingCategory, severity: Severity, techniques=None) -> Finding:
    return Finding(
        title="t",
        category=category,
        severity=severity,
        evidence="e",
        mitre_techniques=list(techniques or []),
    )


class TechniqueResolutionTests(unittest.TestCase):
    def test_explicit_techniques_win(self) -> None:
        f = _finding(FindingCategory.PORT, Severity.HIGH, ["T1210"])
        self.assertEqual(mitre.techniques_for_finding(f), ["T1210"])

    def test_category_fallback_for_unmapped_finding(self) -> None:
        f = _finding(FindingCategory.DNS, Severity.MEDIUM)
        self.assertEqual(mitre.techniques_for_finding(f), ["T1590.002"])

    def test_info_findings_get_no_fallback(self) -> None:
        f = _finding(FindingCategory.TLS, Severity.INFO)
        self.assertEqual(mitre.techniques_for_finding(f), [])

    def test_names_and_tactics_resolve(self) -> None:
        self.assertEqual(mitre.technique_name("T1190"), "Exploit Public-Facing Application")
        self.assertEqual(mitre.technique_tactic("T1190"), "Initial Access")
        self.assertEqual(mitre.technique_name("T9999"), "T9999")
        self.assertEqual(mitre.technique_tactic("T9999"), "Unknown")


class CoverageTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        r = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
        r.findings = [
            _finding(FindingCategory.APPLICATION, Severity.HIGH, ["T1190"]),
            _finding(FindingCategory.PORT, Severity.HIGH),  # -> T1046
            _finding(FindingCategory.PORT, Severity.MEDIUM),  # -> T1046 again
        ]
        return r

    def test_coverage_counts_and_orders_by_tactic(self) -> None:
        hits = mitre.coverage(self._report())
        ids = [h.technique_id for h in hits]
        self.assertIn("T1190", ids)
        self.assertIn("T1046", ids)
        # T1046 appears twice
        self.assertEqual(next(h for h in hits if h.technique_id == "T1046").count, 2)
        # Initial Access (T1190) precedes Discovery (T1046) in kill-chain order
        self.assertLess(ids.index("T1190"), ids.index("T1046"))

    def test_navigator_layer_is_valid_json_with_scores(self) -> None:
        layer = json.loads(mitre.render_navigator_layer([self._report()]))
        self.assertEqual(layer["domain"], "enterprise-attack")
        techs = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(techs["T1046"], 2)
        self.assertEqual(techs["T1190"], 1)
        self.assertEqual(layer["gradient"]["maxValue"], 2)


if __name__ == "__main__":
    unittest.main()
