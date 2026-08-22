"""Run the LOFO zero-shot protocol across every family that has a sibling.

Writes runs/_lofo/lofo_results.json. Per chakra/evaluate/lofo.py: families
without a within-rail sibling are reported as NOT DEFINED, not scored.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from chakra.evaluate.lofo import SIBLINGS_BY_RAIL, run_lofo  # noqa: E402
from chakra.generate.attacks import ATTACK_FAMILIES  # noqa: E402


def main() -> int:
    out_dir = ROOT / "runs" / "_lofo"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    for code in ATTACK_FAMILIES:
        t0 = time.time()
        res = run_lofo(code)
        if res is None:
            results[code] = {
                "defined": False,
                "reason": f"no within-rail sibling on {ATTACK_FAMILIES[code].rail.value}; "
                "zero-shot is not defined and is not reported",
            }
            print(f"{code}: NOT DEFINED (no sibling)")
            continue
        print(f"{code}: {res.headline()}   [{time.time()-t0:.0f}s]")
        results[code] = {"defined": True, **res.to_dict()}

    payload = {
        "protocol": "LOFO zero-shot per docs/EXPERIMENT_CONTRACT.md §7",
        "threshold_policy": "frozen on sibling-only calibration at 0.5% FPR",
        "results": results,
    }
    (out_dir / "lofo_results.json").write_text(
        json.dumps(payload, indent=2, default=float), encoding="utf-8"
    )
    print(f"\nwritten to {out_dir / 'lofo_results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
