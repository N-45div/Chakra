"""First end-to-end run: F11 through the adaptive loop.

Per the experiment contract, the purpose of the first run is to prove
determinism and stream separation — NOT to produce a headline number. Any
accuracy figure printed here is a smoke-test artefact on a tiny world, not a
result, and does not go anywhere near a slide.
"""

from __future__ import annotations

import sys

from chakra.generate.attacks import ATTACK_FAMILIES
from chakra.loop.orchestrator import Loop, LoopConfig


def main(seed: int = 1000, generations: int = 6) -> int:
    cfg = LoopConfig(
        seed=seed,
        generations=generations,
        pop_params=8,
        episodes_per_param=2,
        n_consumers=250,
        n_merchants=25,
        background_days=1.5,
    )
    loop = Loop(ATTACK_FAMILIES["F11"], cfg)
    results = loop.run()

    print(f"\nChakra smoke run — family F11, seed {seed}")
    print("(smoke-test artefact on a small world; not a reportable result)\n")
    header = f"{'gen':>3} {'evasion':>8} {'recall_pre':>11} {'recall_post':>12} {'legit_fpr':>10} {'novelty':>8}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.generation:>3} {r.evasion_rate:>8.3f} {r.monitor_recall_pre:>11.3f} "
            f"{r.monitor_recall_post:>12.3f} {r.monitor_fpr:>10.4f} {r.novelty_recall:>8.3f}"
        )

    # stream separation, asserted at runtime as well as in tests
    for r in results:
        keys = list(r.stream_ids)
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                assert not (r.stream_ids[a] & r.stream_ids[b]), (
                    f"gen {r.generation}: {a} and {b} overlap"
                )
    print("\nstream separation: OK (no shared event ids across streams, all generations)")

    best = results[-1].best_params
    if best:
        print("\nmost evasive parameter vector at final generation:")
        for k, v in best.items():
            print(f"  {k:>20} = {v:.3f}")
    return 0


if __name__ == "__main__":
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    sys.exit(main(seed))
