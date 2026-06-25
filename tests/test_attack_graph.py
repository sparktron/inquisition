from __future__ import annotations

import unittest
from datetime import datetime, timezone

import attack_graph
from models import (
    Finding,
    FindingCategory,
    MisconfigurationCheck,
    ScanReport,
    Severity,
)


def _report(*names: str, scenarios: dict[str, str] | None = None) -> ScanReport:
    scenarios = scenarios or {}
    r = ScanReport(target="example.com", started_at=datetime.now(timezone.utc))
    r.misconfigurations = [
        MisconfigurationCheck(
            name=n, description="d", severity=Severity.HIGH, evidence="e",
            remediation="r", attack_scenario=scenarios.get(n, ""),
        )
        for n in names
    ]
    return r


def _active(title: str, *, mitre: list[str] | None = None) -> Finding:
    return Finding(
        title=title,
        category=FindingCategory.VULNERABILITY,
        severity=Severity.HIGH,
        evidence="matched",
        mitre_techniques=mitre or [],
    )


class AttackGraphTests(unittest.TestCase):
    def test_empty_when_no_misconfigs(self) -> None:
        g = attack_graph.build_attack_graph(_report())
        self.assertTrue(g.empty)
        self.assertEqual(g.goals, [])

    def test_direct_rce_objective(self) -> None:
        g = attack_graph.build_attack_graph(_report("Redis exposed to internet"))
        states = {goal.state for goal in g.goals}
        self.assertIn("code_exec", states)
        # code_exec is the highest-value objective -> first.
        self.assertEqual(g.goals[0].state, "code_exec")
        # RCE implies data access + lateral movement via consequence edges.
        self.assertIn("data_access", states)
        self.assertIn("lateral", states)

    def test_multi_step_path_env_to_cloud(self) -> None:
        g = attack_graph.build_attack_graph(_report("Environment file publicly accessible"))
        states = {goal.state for goal in g.goals}
        self.assertIn("credentials", states)
        self.assertIn("cloud_account", states)
        cloud = next(goal for goal in g.goals if goal.state == "cloud_account")
        # external -> credentials -> cloud_account (two edges)
        self.assertEqual(len(cloud.path), 2)
        self.assertEqual(cloud.path[0].frm, "external")
        self.assertEqual(cloud.path[-1].to, "cloud_account")

    def test_combo_edge_requires_both_misconfigs(self) -> None:
        partial = attack_graph.build_attack_graph(_report("CSP not configured"))
        self.assertNotIn("session_hijack", {g.state for g in partial.goals})
        both = attack_graph.build_attack_graph(
            _report("CSP not configured", "Session cookies lack security flags")
        )
        self.assertIn("session_hijack", {g.state for g in both.goals})

    def test_on_path_chain_reaches_credentials(self) -> None:
        g = attack_graph.build_attack_graph(_report("HSTS not enabled"))
        states = {goal.state for goal in g.goals}
        self.assertIn("credentials", states)  # via on_path consequence edge

    def test_mermaid_is_wellformed(self) -> None:
        g = attack_graph.build_attack_graph(_report("Redis exposed to internet"))
        mer = attack_graph.to_mermaid(g)
        self.assertTrue(mer.startswith("flowchart LR"))
        self.assertIn("code_exec", mer)
        self.assertIn("-->", mer)
        # only reachable nodes are emitted
        self.assertNotIn("phishing", mer)

    def test_summary_lines_describe_paths(self) -> None:
        g = attack_graph.build_attack_graph(_report("SMB exposed to internet"))
        text = "\n".join(attack_graph.summary_lines(g))
        self.assertIn("Code execution", text)
        self.assertIn("path:", text)

    def test_feasibility_discounts_on_path_routes(self) -> None:
        # Credentials reached only via an on-path MITM chain (HSTS) should have
        # lower priority than its raw value because the path is hard to walk.
        g = attack_graph.build_attack_graph(_report("HSTS not enabled"))
        cred = next(goal for goal in g.goals if goal.state == "credentials")
        self.assertLess(cred.feasibility, 1.0)
        self.assertLess(cred.priority, cred.value)

    def test_remote_rce_outranks_on_path_objective(self) -> None:
        g = attack_graph.build_attack_graph(
            _report("Redis exposed to internet", "HSTS not enabled")
        )
        # Remote unauth RCE (feasibility 1.0) is the top objective.
        self.assertEqual(g.goals[0].state, "code_exec")
        self.assertEqual(g.goals[0].feasibility, 1.0)


class ActiveScanEdgeTests(unittest.TestCase):
    def test_confirmed_xss_creates_session_hijack_goal(self) -> None:
        r = _report()
        r.findings = [_active("[active] Reflected XSS in search")]
        g = attack_graph.build_attack_graph(r)
        hijack = next(goal for goal in g.goals if goal.state == "session_hijack")
        self.assertTrue(hijack.confirmed)
        self.assertEqual(hijack.feasibility, 1.0)

    def test_classify_by_mitre_when_title_is_opaque(self) -> None:
        # No keyword in the title; class falls back to the MITRE technique.
        r = _report()
        r.findings = [_active("[active] CVE-2021-1234", mitre=["T1059"])]
        g = attack_graph.build_attack_graph(r)
        self.assertIn("code_exec", {goal.state for goal in g.goals})

    def test_confirmed_path_outranks_modeled_higher_value(self) -> None:
        # A modeled RCE (value 100) vs a confirmed XSS (value 60): the proven
        # path must surface first even though its raw value is lower.
        r = _report("Redis exposed to internet")
        r.findings = [_active("[active] Stored XSS")]
        g = attack_graph.build_attack_graph(r)
        self.assertTrue(g.goals[0].confirmed)
        self.assertEqual(g.goals[0].state, "session_hijack")

    def test_confirmed_edge_renders_thick_in_mermaid(self) -> None:
        r = _report()
        r.findings = [_active("[active] SQL injection")]
        mer = attack_graph.to_mermaid(attack_graph.build_attack_graph(r))
        self.assertIn("==>", mer)
        self.assertIn("✓", mer)  # ✓ marker

    def test_summary_flags_confirmed_objective(self) -> None:
        r = _report()
        r.findings = [_active("[active] Remote Code Execution")]
        text = "\n".join(attack_graph.summary_lines(attack_graph.build_attack_graph(r)))
        self.assertIn("CONFIRMED via active scan", text)

    def test_non_active_findings_are_ignored(self) -> None:
        r = _report()
        r.findings = [
            Finding(title="Reflected XSS hint", category=FindingCategory.HTTP_HEADER,
                    severity=Severity.LOW, evidence="e"),
        ]
        self.assertTrue(attack_graph.build_attack_graph(r).empty)

    def test_duplicate_active_class_adds_one_edge(self) -> None:
        r = _report()
        r.findings = [_active("[active] XSS on /a"), _active("[active] XSS on /b")]
        g = attack_graph.build_attack_graph(r)
        xss_edges = [e for e in g.edges if e.confirmed and e.to == "session_hijack"]
        self.assertEqual(len(xss_edges), 1)

    def test_story_notes_confirmed_path(self) -> None:
        r = _report()
        r.findings = [_active("[active] Remote Code Execution")]
        self.assertIn("confirmed exploitable", attack_graph.attack_story(r))


class AttackStoryTests(unittest.TestCase):
    def test_empty_when_no_objectives(self) -> None:
        self.assertEqual(attack_graph.attack_story(_report()), "")

    def test_story_names_top_objective_and_path(self) -> None:
        r = _report("Redis exposed to internet",
                    scenarios={"Redis exposed to internet": "Attacker writes a webshell via CONFIG SET."})
        story = attack_graph.attack_story(r)
        self.assertIn("Code execution", story)
        self.assertIn("example.com", story)
        self.assertIn("Concretely:", story)
        self.assertIn("webshell", story)

    def test_narrator_hook_is_used_when_provided(self) -> None:
        r = _report("Redis exposed to internet")
        captured = {}

        def fake(prompt: str) -> str:
            captured["prompt"] = prompt
            return "LLM-WRITTEN STORY"

        out = attack_graph.attack_story(r, narrator=fake)
        self.assertEqual(out, "LLM-WRITTEN STORY")
        self.assertIn("Objective:", captured["prompt"])


class BuildAttackGraphMemoTests(unittest.TestCase):
    def test_repeat_calls_compute_once(self) -> None:
        from unittest import mock
        r = _report("exposed_git_directory")
        with mock.patch.object(
            attack_graph, "_compute_attack_graph",
            wraps=attack_graph._compute_attack_graph,
        ) as spy:
            g1 = attack_graph.build_attack_graph(r)
            g2 = attack_graph.build_attack_graph(r)
            attack_graph.attack_story(r)  # also builds the graph internally
        self.assertIs(g1, g2)
        self.assertEqual(spy.call_count, 1)  # cached on the report instance

    def test_cache_invalidates_on_misconfig_change(self) -> None:
        from unittest import mock
        r = _report("exposed_git_directory")
        attack_graph.build_attack_graph(r)
        r.misconfigurations = list(r.misconfigurations) + [
            MisconfigurationCheck(
                name="exposed_env_file", description="d", severity=Severity.HIGH,
                evidence="e", remediation="r", attack_scenario="",
            )
        ]
        with mock.patch.object(
            attack_graph, "_compute_attack_graph",
            wraps=attack_graph._compute_attack_graph,
        ) as spy:
            attack_graph.build_attack_graph(r)
        self.assertEqual(spy.call_count, 1)  # recomputed after the change


if __name__ == "__main__":
    unittest.main()
