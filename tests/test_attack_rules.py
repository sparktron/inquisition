from __future__ import annotations

import unittest

import attack_rules
from models import Finding, FindingCategory, MisconfigurationCheck, Severity
from vuln_correlation import derive_misconfigurations, detect_attack_chains


def _mc(name: str) -> MisconfigurationCheck:
    return MisconfigurationCheck(
        name=name, description="d", severity=Severity.HIGH, evidence="e", remediation="r"
    )


def _finding(category: FindingCategory, title: str, severity: Severity = Severity.HIGH, cpe: str = "", mitre: list[str] | None = None) -> Finding:
    return Finding(
        title=title, category=category, severity=severity, evidence="e",
        cpe=cpe, mitre_techniques=list(mitre or []),
    )


class LoaderTests(unittest.TestCase):
    def test_misconfig_rules_load_and_coerce(self) -> None:
        rules = attack_rules.load_misconfig_rules()
        self.assertTrue(rules)
        sample = rules[0]
        self.assertIsInstance(sample["severity"], Severity)
        self.assertTrue(all(isinstance(c, FindingCategory) for c in sample["categories"]))

    def test_chain_rules_load(self) -> None:
        chains = attack_rules.load_chain_rules()
        names = {c.chain.name for c in chains}
        self.assertIn("SSL Stripping Credential Harvest", names)


class ConditionTests(unittest.TestCase):
    def test_misconfig_condition(self) -> None:
        c = attack_rules.Condition(misconfig="HSTS not enabled")
        self.assertTrue(c.matches([_mc("HSTS not enabled")], []))
        self.assertFalse(c.matches([_mc("Something else")], []))

    def test_finding_attribute_condition(self) -> None:
        c = attack_rules.Condition(category="port", title_contains="6379", min_severity="high")
        good = [_finding(FindingCategory.PORT, "Open port 6379/Redis", Severity.HIGH)]
        weak = [_finding(FindingCategory.PORT, "Open port 6379/Redis", Severity.LOW)]
        wrong_cat = [_finding(FindingCategory.DNS, "Open port 6379/Redis", Severity.HIGH)]
        self.assertTrue(c.matches([], good))
        self.assertFalse(c.matches([], weak))     # below severity threshold
        self.assertFalse(c.matches([], wrong_cat))  # wrong category

    def test_mitre_and_cpe_conditions(self) -> None:
        c = attack_rules.Condition(mitre="T1190", cpe_contains="wordpress")
        f = _finding(FindingCategory.APPLICATION, "x", cpe="cpe:2.3:a:wordpress:wordpress", mitre=["T1190"])
        self.assertTrue(c.matches([], [f]))
        self.assertFalse(c.matches([], [_finding(FindingCategory.APPLICATION, "x", mitre=["T1190"])]))


class IntegrationTests(unittest.TestCase):
    def test_chain_triggers_on_required_misconfigs(self) -> None:
        findings = [
            _finding(FindingCategory.HTTP_HEADER, "Missing header: Strict-Transport-Security", Severity.MEDIUM),
            _finding(FindingCategory.HTTP_HEADER, "No HTTP-to-HTTPS redirect", Severity.MEDIUM),
        ]
        misconfigs = derive_misconfigurations(findings)
        chains = detect_attack_chains(misconfigs, findings)
        names = {c.name for c in chains}
        self.assertIn("SSL Stripping Credential Harvest", names)

    def test_no_chain_when_conditions_unmet(self) -> None:
        findings = [_finding(FindingCategory.HTTP_HEADER, "Missing header: Strict-Transport-Security", Severity.MEDIUM)]
        misconfigs = derive_misconfigurations(findings)
        chains = detect_attack_chains(misconfigs, findings)
        self.assertNotIn("SSL Stripping Credential Harvest", {c.name for c in chains})

    def test_unknown_condition_field_rejected(self) -> None:
        from unittest.mock import patch

        bad = {"name": "x", "description": "d", "steps": ["s"], "requires": [{"bogus": "1"}]}
        attack_rules.load_chain_rules.cache_clear()
        try:
            with patch("attack_rules._load_yaml", return_value=[bad]):
                with self.assertRaises(ValueError):
                    attack_rules.load_chain_rules()
        finally:
            attack_rules.load_chain_rules.cache_clear()


if __name__ == "__main__":
    unittest.main()
