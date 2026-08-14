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
        n_consumers=250,
        n_merchants=25,
        world_span_days=1.5,
    )
    loop = Loop(ATTACK_FAMILIES["F11"], cfg)
    results = loop.run()

    print(f"\nChakra smoke run — family F11, seed {seed}")
    print("(smoke-test artefact on a small world; NOT a reportable result)\n")
    header = (
        f"{'gen':>3} {'ep_evade':>9} {'yield':>7} {'recall_pre':>11} "
        f"{'recall_post':>12} {'fpr_pre':>8} {'fpr_post':>9} {'prev':>7}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.generation:>3} {r.episode_evasion:>9.3f} {r.attacker_yield:>7.2f} "
            f"{r.monitor_recall_pre:>11.3f} {r.monitor_recall_post:>12.3f} "
            f"{r.monitor_fpr_pre:>8.4f} {r.monitor_fpr_post:>9.4f} {r.prevalence:>7.4f}"
        )

    # stream separation, asserted at runtime as well as in tests
    for r in results:
        overlap = r.stream_ids.get("monitor", set()) & r.stream_ids.get("training", set())
        assert not overlap, f"gen {r.generation}: monitor and training overlap"
    print("\nstream separation: OK (monitor and training share no event ids)")

    best = results[-1].best_params
    if best:
        print("\nmost evasive parameter vector at final generation:")
        for k, v in best.items():
            print(f"  {k:>20} = {v:.3f}")
    return 0


if __name__ == "__main__":
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    sys.exit(main(seed))
