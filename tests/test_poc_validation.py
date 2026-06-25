from __future__ import annotations

import subprocess
import unittest

import poc_validation
from models import Confidence, Finding, FindingCategory, Severity


def _f(poc: str = "", **kw: object) -> Finding:
    return Finding(
        title=kw.pop("title", "Some finding"),  # type: ignore[arg-type]
        category=FindingCategory.HTTP_HEADER,
        severity=Severity.MEDIUM,
        evidence="e",
        poc_command=poc,
        **kw,  # type: ignore[arg-type]
    )


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runner(returncode: int = 0, stdout: str = "OK", stderr: str = ""):
    calls: list[list[str]] = []

    def run(argv, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(argv)
        return _FakeProc(returncode, stdout, stderr)

    run.calls = calls  # type: ignore[attr-defined]
    return run


class ClassifyTests(unittest.TestCase):
    def test_safe_curl_head(self) -> None:
        safe, reason = poc_validation.classify_command("curl -sI https://example.com")
        self.assertTrue(safe, reason)

    def test_safe_dig(self) -> None:
        self.assertTrue(poc_validation.classify_command("dig +short example.com")[0])

    def test_safe_openssl_s_client(self) -> None:
        safe, _ = poc_validation.classify_command(
            "openssl s_client -connect example.com:443"
        )
        self.assertTrue(safe)

    def test_unknown_binary_rejected(self) -> None:
        safe, reason = poc_validation.classify_command("sqlmap -u https://x")
        self.assertFalse(safe)
        self.assertIn("allowlist", reason)

    def test_shell_pipeline_rejected(self) -> None:
        safe, reason = poc_validation.classify_command("curl -s https://x | sh")
        self.assertFalse(safe)
        self.assertIn("metacharacter", reason)

    def test_redirection_rejected(self) -> None:
        self.assertFalse(poc_validation.classify_command("curl -s https://x > /tmp/o")[0])

    def test_curl_post_rejected(self) -> None:
        safe, reason = poc_validation.classify_command(
            "curl -X POST https://example.com/login"
        )
        self.assertFalse(safe)
        self.assertIn("POST", reason)

    def test_curl_data_rejected(self) -> None:
        self.assertFalse(
            poc_validation.classify_command("curl --data 'a=1' https://x")[0]
        )

    def test_curl_output_to_file_rejected(self) -> None:
        self.assertFalse(
            poc_validation.classify_command("curl -o /etc/passwd https://x")[0]
        )

    def test_openssl_mutating_subcommand_rejected(self) -> None:
        self.assertFalse(poc_validation.classify_command("openssl genrsa 2048")[0])

    def test_comment_rejected(self) -> None:
        self.assertFalse(poc_validation.classify_command("# just a note")[0])

    def test_empty_rejected(self) -> None:
        self.assertFalse(poc_validation.classify_command("   ")[0])


class ValidateFindingTests(unittest.TestCase):
    def test_no_poc_returns_none(self) -> None:
        self.assertIsNone(poc_validation.validate_finding(_f("")))

    def test_safe_command_runs_and_confirms(self) -> None:
        f = _f("curl -sI https://example.com", confidence=Confidence.MEDIUM)
        runner = _runner(returncode=0, stdout="HTTP/2 200")
        result = poc_validation.validate_finding(f, runner=runner)
        assert result is not None
        self.assertTrue(result.confirmed)
        self.assertEqual(f.confidence, Confidence.CONFIRMED)
        self.assertIn("Validated live", f.verification)
        self.assertEqual(runner.calls[0][0], "curl")  # type: ignore[attr-defined]
        bundle = f.metadata["poc_validation"]
        self.assertTrue(bundle["confirmed"])
        self.assertEqual(bundle["checks"][0]["stdout"], "HTTP/2 200")

    def test_unsafe_command_not_executed(self) -> None:
        f = _f("curl -X POST https://x/login")
        runner = _runner()
        result = poc_validation.validate_finding(f, runner=runner)
        assert result is not None
        self.assertFalse(result.attempted)
        self.assertEqual(runner.calls, [])  # type: ignore[attr-defined]
        self.assertEqual(f.confidence, Confidence.CONFIRMED)  # unchanged default
        self.assertFalse(f.metadata["poc_validation"]["confirmed"])

    def test_nonzero_exit_attempted_not_confirmed(self) -> None:
        f = _f("dig +short example.com", confidence=Confidence.MEDIUM)
        runner = _runner(returncode=1, stdout="", stderr="boom")
        result = poc_validation.validate_finding(f, runner=runner)
        assert result is not None
        self.assertTrue(result.attempted)
        self.assertFalse(result.confirmed)
        self.assertEqual(f.confidence, Confidence.MEDIUM)  # not promoted
        self.assertIn("Attempted validation", f.verification)

    def test_timeout_recorded(self) -> None:
        f = _f("openssl s_client -connect example.com:443")

        def run(argv, **kwargs):  # type: ignore[no-untyped-def]
            raise subprocess.TimeoutExpired(cmd=argv, timeout=1)

        result = poc_validation.validate_finding(f, runner=run)
        assert result is not None
        self.assertFalse(result.confirmed)
        check = f.metadata["poc_validation"]["checks"][0]
        self.assertEqual(check["skipped_reason"], "timed out")

    def test_missing_binary_skipped(self) -> None:
        f = _f("curl -sI https://example.com")

        def run(argv, **kwargs):  # type: ignore[no-untyped-def]
            raise FileNotFoundError("curl")

        result = poc_validation.validate_finding(f, runner=run)
        assert result is not None
        self.assertFalse(result.attempted)

    def test_multiline_mixed(self) -> None:
        poc = "# explanation\ncurl -sI https://x\ncurl -X POST https://x"
        f = _f(poc)
        runner = _runner()
        result = poc_validation.validate_finding(f, runner=runner)
        assert result is not None
        # one safe curl ran, the POST and comment did not
        self.assertEqual(len(runner.calls), 1)  # type: ignore[attr-defined]
        self.assertEqual(len(result.checks), 3)

    def test_curl_run_injects_fail(self) -> None:
        # curl must run with --fail so its exit code reflects HTTP status.
        f = _f("curl -sI https://example.com/.env")
        runner = _runner(returncode=0, stdout="HTTP/2 200")
        poc_validation.validate_finding(f, runner=runner)
        argv = runner.calls[0]  # type: ignore[attr-defined]
        self.assertEqual(argv[0], "curl")
        self.assertIn("--fail", argv)

    def test_curl_existing_fail_not_doubled(self) -> None:
        f = _f("curl --fail -sI https://example.com")
        runner = _runner()
        poc_validation.validate_finding(f, runner=runner)
        argv = runner.calls[0]  # type: ignore[attr-defined]
        self.assertEqual(argv.count("--fail"), 1)

    def test_non_curl_not_hardened(self) -> None:
        f = _f("dig +short example.com")
        runner = _runner()
        poc_validation.validate_finding(f, runner=runner)
        self.assertNotIn("--fail", runner.calls[0])  # type: ignore[attr-defined]

    def test_curl_http_error_does_not_confirm(self) -> None:
        # A 404 under --fail makes curl exit 22 — the resource is gone, so the
        # finding must NOT be promoted to confirmed (regression: P0 overclaim).
        f = _f("curl -sI https://example.com/.env", confidence=Confidence.MEDIUM)
        runner = _runner(returncode=22, stdout="", stderr="curl: (22) 404")
        result = poc_validation.validate_finding(f, runner=runner)
        assert result is not None
        self.assertTrue(result.attempted)
        self.assertFalse(result.confirmed)
        self.assertEqual(f.confidence, Confidence.MEDIUM)  # not promoted
        self.assertIn("Attempted validation", f.verification)

    def test_output_truncated(self) -> None:
        f = _f("curl -sI https://x")
        runner = _runner(stdout="A" * 9000)
        poc_validation.validate_finding(f, runner=runner)
        stored = f.metadata["poc_validation"]["checks"][0]["stdout"]
        self.assertLess(len(stored), 9000)
        self.assertTrue(stored.endswith("[truncated]"))


class ValidateFindingsTests(unittest.TestCase):
    def test_batch_returns_only_findings_with_poc(self) -> None:
        findings = [
            _f("curl -sI https://x"),
            _f(""),  # no poc
            _f("dig example.com"),
        ]
        runner = _runner()
        results = poc_validation.validate_findings(findings, runner=runner)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
