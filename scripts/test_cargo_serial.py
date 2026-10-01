"""Focused tests for the portable Cargo runner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CargoSerialRunner(unittest.TestCase):
    def test_external_root_and_evidence_are_optional_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            evidence = base / "evidence"
            binaries = base / "bin"
            root.mkdir()
            binaries.mkdir()
            cargo = binaries / "cargo"
            cargo.write_text("#!/bin/sh\nprintf 'cwd=%s args=%s\\n' \"$PWD\" \"$*\"\nprintf 'diagnostic\\n' >&2\n")
            cargo.chmod(0o700)
            environment = os.environ.copy()
            environment.update(
                PATH=str(binaries) + os.pathsep + environment.get("PATH", ""),
                CTXQL_CARGO_ROOT=str(root),
                CTXQL_CARGO_EVIDENCE=str(evidence),
            )
            script = Path(__file__).with_name("cargo_serial.py")
            result = subprocess.run(
                [sys.executable, script, "cargo", "test", "--locked"],
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            record_path = next(evidence.glob("*.json"))
            record = json.loads(record_path.read_text())
            self.assertEqual(record["cwd"], str(root.resolve()))
            self.assertEqual(record["argv"], ["cargo", "test", "--locked"])
            self.assertIn("cwd=" + str(root.resolve()), result.stdout)
            self.assertIn("diagnostic", result.stdout)
            self.assertTrue((evidence.parent / "cargo-serial.lock").is_file())


if __name__ == "__main__":
    unittest.main()
