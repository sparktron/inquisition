from __future__ import annotations

import unittest
from datetime import datetime, timezone

import attack_graph
from models import MisconfigurationCheck, ScanReport, Severity


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


if __name__ == "__main__":
    unittest.main()
