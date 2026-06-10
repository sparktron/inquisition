from __future__ import annotations

import unittest

from models import FindingCategory, ScanConfig
from modules import ALL_MODULES


class DryRunModuleTests(unittest.TestCase):
    def test_every_module_returns_one_dry_run_finding_without_network(self) -> None:
        config = ScanConfig(target="example.com", dry_run=True, rate_limit=0)

        for module_cls in ALL_MODULES:
            with self.subTest(module=module_cls.__name__):
                findings = module_cls(config).run()

                self.assertEqual(len(findings), 1)
                self.assertIn("dry-run", findings[0].title.lower())
                self.assertEqual(findings[0].severity.value, "info")
                self.assertIsInstance(findings[0].category, FindingCategory)


if __name__ == "__main__":
    unittest.main()
