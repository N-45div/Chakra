"""The load-bearing guarantee: attacks emit raw actions, never features.

If an attack could import or write to the feature layer, the detector would be
learning the attack author's rules and every hold-out number would be
meaningless. These tests make that structurally impossible to do by accident.
"""

import ast
import pathlib

ATTACKS_DIR = pathlib.Path(__file__).resolve().parents[1] / "chakra" / "generate" / "attacks"


def _imports_of(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_attacks_never_import_feature_layer():
    for py in ATTACKS_DIR.glob("*.py"):
        mods = _imports_of(py)
        offenders = {m for m in mods if "schema.features" in m or m.endswith("features")}
        assert not offenders, f"{py.name} imports the feature layer: {offenders}"


def test_attack_payloads_contain_no_feature_names():
    """No attack file may mention a registered feature name in a payload — a
    crude but effective tripwire against someone writing velocity_10m directly."""
    from chakra.schema.features import registered

    feature_names = set(registered().keys())
    for py in ATTACKS_DIR.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for fname in feature_names:
            assert f'"{fname}"' not in src and f"'{fname}'" not in src, (
                f"{py.name} references feature {fname!r} — attacks must emit raw "
                f"events, not features"
            )
