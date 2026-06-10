from __future__ import annotations

import unittest

import analysis_kb


class AnalysisKbTests(unittest.TestCase):
    def test_entries_have_required_schema(self) -> None:
        entries = analysis_kb.entries()

        self.assertGreater(len(entries), 10)
        seen_keywords: set[str] = set()
        for keyword, entry in entries:
            with self.subTest(keyword=keyword):
                self.assertEqual(keyword, keyword.lower())
                self.assertNotIn(keyword, seen_keywords)
                seen_keywords.add(keyword)
                self.assertEqual(set(entry), {"analysis", "remediation"})
                self.assertTrue(entry["analysis"].strip())
                self.assertTrue(entry["remediation"].strip())

    def test_lookup_matches_first_keyword_in_order(self) -> None:
        exact = analysis_kb.lookup("Certificate EXPIRED")
        general = analysis_kb.lookup("Certificate expiring soon")

        assert exact is not None
        assert general is not None
        self.assertIn("hard-coded validity window", exact["analysis"])
        self.assertIn("will expire within 30 days", general["analysis"])

    def test_lookup_returns_none_for_unknown_title(self) -> None:
        self.assertIsNone(analysis_kb.lookup("completely unknown finding"))


if __name__ == "__main__":
    unittest.main()
