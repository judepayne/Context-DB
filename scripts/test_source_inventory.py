#!/usr/bin/env python3
"""Source-level checks for current semantic authority boundaries."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "crates"


def production_rust():
    for path in list(CRATES.glob("*/src/**/*.rs")) + list(CRATES.glob("*/build.rs")):
        if "conflicted copy" not in path.name:
            yield path


class SourceInventory(unittest.TestCase):
    def test_production_has_no_obsolete_authority_symbols(self):
        prohibited = [
            "PreparedInterpretation",
            "native_interpretation",
            "ctxql-native-interpretation",
            "urn:ctxql:native-interpretation",
            "CTXQL_NATIVE_INTERPRETATION_BUILD",
            "CDB_NATIVE_INTERPRETATION_BUILD",
        ]
        hits = []
        for path in production_rust():
            text = path.read_text(encoding="utf-8")
            for token in prohibited:
                if token in text:
                    hits.append(f"{path.relative_to(ROOT)}: {token}")
        self.assertEqual(hits, [])

    def test_instance_v3_dispatch_uses_current_recording(self):
        service = (ROOT / "crates/cdb-service/src/service.rs").read_text(encoding="utf-8")
        preparation = (ROOT / "crates/cdb-service/src/service/preparation.rs").read_text(encoding="utf-8")
        self.assertIn("prepared.execute_recorded_v5(operation_hash)", service)
        self.assertIn("execute_recorded_v3_portable", service)
        self.assertIn('"semantic instance/v3 requires recording v5"', preparation)
        self.assertNotIn("execute_recorded_v3(", preparation)

    def test_semantic_role_cannot_alias_control_backend_type(self):
        service = (ROOT / "crates/cdb-service/src/service.rs").read_text(encoding="utf-8")
        semantic = (ROOT / "crates/cdb-backend-fluree/src/semantic.rs").read_text(encoding="utf-8")
        self.assertIn("semantic: Option<Arc<FlureeSemanticLedger>>", service)
        self.assertNotIn("semantic: Option<Arc<FlureeBackend>>", service)
        self.assertNotIn("FlureeBackend", semantic)


if __name__ == "__main__":
    unittest.main()
