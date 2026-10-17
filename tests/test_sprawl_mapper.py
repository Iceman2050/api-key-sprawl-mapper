"""Tests for api-key-sprawl-mapper.

Builds a real fixture tree with fake-but-realistic key material and runs
the actual mapper against it. No mocks.
"""

import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import sprawl_mapper  # noqa: E402

# Fake keys: realistic shape, not real secrets.
# Built by concatenation so no secret-shaped literal ever lands in this file
# (GitHub push protection scans for those patterns).
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_" + "abc123DEF456ghi789JKL012mno345PQR678"


def build_fixture():
    root = tempfile.mkdtemp(prefix="sprawl-fixture-")
    files = {
        "backend/config.py": f'STRIPE_SECRET = "{STRIPE_KEY}"\n',
        "backend/payments.py": f"stripe.api_key = '{STRIPE_KEY}'\n",
        "scripts/seed.sh": f"export STRIPE_KEY={STRIPE_KEY}\n",
        "ci/deploy.yml": f"token: {GITHUB_TOKEN}\n",
        "README.md": "# nothing secret here\n",
    }
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
    return root


def run_mapper(root, extra=()):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sprawl_mapper.main([root, *extra])
    return code, buf.getvalue()


class TestSprawlMapper(unittest.TestCase):
    def test_sprawl_detected_with_exact_counts(self):
        root = build_fixture()
        code, out = run_mapper(root)
        self.assertEqual(code, 0, "no --fail-on-sprawl: exit 0 even with sprawl")
        self.assertIn("SPRAWL (1)", out)
        self.assertIn("[Stripe]", out)
        self.assertIn("3 files", out)
        self.assertIn("3 occurrences", out)

    def test_sprawl_lists_all_three_files(self):
        root = build_fixture()
        _, out = run_mapper(root)
        self.assertIn("backend/config.py", out)
        self.assertIn("backend/payments.py", out)
        self.assertIn("scripts/seed.sh", out)

    def test_contained_key_listed(self):
        root = build_fixture()
        _, out = run_mapper(root)
        self.assertIn("CONTAINED (1)", out)
        self.assertIn("[GitHub]", out)
        self.assertIn("ci/deploy.yml", out)

    def test_fail_on_sprawl_exit_code(self):
        root = build_fixture()
        code, _ = run_mapper(root, extra=("--fail-on-sprawl",))
        self.assertEqual(code, 1)

    def test_no_raw_key_material_in_output(self):
        root = build_fixture()
        _, out = run_mapper(root)
        self.assertNotIn(STRIPE_KEY, out)
        self.assertNotIn(GITHUB_TOKEN, out)

    def test_redacted_display_format(self):
        root = build_fixture()
        _, out = run_mapper(root)
        self.assertIn("sk_live_...***", out)
        self.assertIn("ghp_abc1...***", out)

    def test_fingerprint_matches_sha256(self):
        root = build_fixture()
        keys = sprawl_mapper.scan(root)
        expected = hashlib.sha256(STRIPE_KEY.encode()).hexdigest()
        self.assertEqual(keys[STRIPE_KEY]["fingerprint"], expected)

    def test_clean_tree_clean_report(self):
        root = tempfile.mkdtemp(prefix="sprawl-clean-")
        with open(os.path.join(root, "app.py"), "w") as fh:
            fh.write('print("hello")\n')
        code, out = run_mapper(root)
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_ten_plus_services_in_table(self):
        services = {s for s, _, _ in sprawl_mapper.PATTERNS}
        self.assertGreaterEqual(len(services), 10, f"only {services}")

    def test_each_service_pattern_matches(self):
        # One realistic sample per pattern, in PATTERNS order.
        # Concatenated so no secret-shaped literal lands in this file.
        samples = [
            "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
            "AKIA" + "IOSFODNN7EXAMPLE",
            "ghp_" + "abc123DEF456ghi789JKL012mno345PQR678",
            "github_pat_" + "abc123DEF456ghi789JKL012",
            "xoxb-" + "123456789012-abcdefghij",
            "sk-proj-" + "abc123DEF456ghi789JKL012",
            "SG." + "abc123DEF456ghi789JKL012",
            "SK" + "a" * 32,
            "key-" + "b" * 32,
            "AIza" + "c" * 35,
            "dop_v1_" + "d" * 64,
            'api_key = "supersecretvalue12345"',
        ]
        self.assertEqual(len(samples), len(sprawl_mapper.PATTERNS))
        for (service, pattern, group), sample in zip(sprawl_mapper.PATTERNS, samples):
            m = pattern.search(sample)
            self.assertIsNotNone(m, f"{service} pattern failed on sample")
            self.assertTrue(m.group(group))


if __name__ == "__main__":
    unittest.main()
