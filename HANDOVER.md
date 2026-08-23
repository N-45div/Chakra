# Chakra — handover

**Repo:** https://github.com/N-45div/Chakra · 76 tests passing
**Deadline:** 31 Aug 2026, 11:59 PM IST · **Submitted via:** Kaggle → Writeups tab

---

## 1. Deploy the dashboard to Render (~2 min, blocked on you)

I cannot authenticate to Render. Everything else is prepared and verified from a clean clone.

1. https://dashboard.render.com → **New** → **Blueprint**
2. Connect repo **N-45div/Chakra**
3. Render reads `render.yaml` → click **Apply**

Static site, so it never sleeps and cannot cold-start mid-demo. Build is pure stdlib
(`python scripts/build_dashboard.py`) — no requirements file to break.

You'll get `https://chakra-dashboard.onrender.com`. **That URL is submission artifact #3.**

---

## 2. Rotate the Kaggle token (do this)

The token you pasted is in the chat transcript. Rotate at https://www.kaggle.com/settings
→ API → Expire Token. It's stored locally at `~/.kaggle/access_token`, which is gitignored
and was never committed.

---

## 3. Unlock IEEE-CIS (one browser click)

Lane A currently runs on ULB only. IEEE-CIS returns 403 because competition rules are
unaccepted. I deliberately did **not** substitute a third-party mirror — unverified
provenance is the failure mode this project has fought throughout.

1. Visit https://www.kaggle.com/c/ieee-fraud-detection/rules → **I Understand and Accept**
2. Then run:

```bash
cd C:/Users/DivijN/chakra
./.venv/Scripts/python.exe -c "import kaggle; kaggle.api.authenticate(); kaggle.api.competition_download_files('ieee-fraud-detection', path='data/raw/ieee', quiet=False)"
```

Lane A's harness is dataset-agnostic; point `run_lane_a()` at the IEEE CSV with the
appropriate `label_col`/`time_col` and it works unchanged.

---

## 4. Finish the registered runs (long, unattended)

**DONE — 100/100.** All five families completed 20 seeds × 10 generations:

| Family | Status | Notes |
|---|---|---|
| F5  | 20/20 ✅ | post-F-008 tree |
| F8  | 20/20 ✅ | re-run after F-008 (first ten seeds optimised backwards) |
| F6  | 20/20 ✅ | |
| F11 | 20/20 ✅ | |
| F10 | 20/20 ✅ | re-run after F-009 (shared genuine agents) |

LOFO re-run on the final tree; dashboard and walkthrough rebuilt; results
analysis in `docs/FINDINGS.md` F-010.

---

## 5. Look at the rendered artifacts (I have not)

**This is the gap I'd fix first.** I verified the dashboard and walkthrough by grepping
markup and extracting text — I never viewed either rendered. For the artifact that decides
podiums, that isn't good enough.

- Open `dashboard/index.html` in a browser. Check both light and dark mode, chart label
  collisions, SVG geometry, the replay explorer scrubber.
- Open `docs/Walkthrough.docx` in Word. Check table overflow, page breaks, fonts.

---

## 6. F8's ten seeds were re-run (resolved)

Fixed in commit `91b51c2` and re-run: all 20 F8 seeds are post-fix, and F-008
records the defect and its measurement in `docs/FINDINGS.md`. Nothing further
to do.

---

## 7. F10 — agent fan-out is now a real trade (resolved)

Fixed: the genuine population draws assistants from a shared provider pool with
adoption churn (commit after `91b51c2`), F10's 20 seeds re-run, and F-009's
status updated in `docs/FINDINGS.md`. Both claims — the cliff and the
non-load-bearing ablation — were addressed by the population fix; the headline
numbers in F-010 are the post-fix runs.

---

## 8. Known issues worth your judgement

**Small-n families in the efficacy table.** F10 (n=2) and F11 (n=3) sit in the same table
as F5 (n=20). This project retracted finding F-002 precisely for reading one seed as a
result. The table does show a Seeds column, but consider marking n<5 rows explicitly as
not reportable — or just finish the registered runs (§4), which removes the problem.

**F6: the logistic baseline beats the boosted model on zero-shot** — AUPRC 0.981 vs 0.613,
recall 0.991 vs 0.602. That is the baseline doing its job: it suggests the booster fits
sibling-specific structure that does not transfer. Worth a paragraph in the deck as a real
methodological finding, not a bug to hide.

**Lane A fidelity is weak and openly reported.** Discriminator AUC 0.998 — our Gaussian
copula produces rows trivially distinguishable from real ones, and TSTR AUC is 0.507
(chance). Fidelity is a *scored* criterion. If you want to improve it, CTGAN in place of
the copula is the obvious next step. If you'd rather not, the current honest framing is
defensible — but expect a judge to ask.

**The review workflow completed after I stopped.** Its two confirmed findings are §6 and
§7 above — one fixed, one open. 48 agents, four lenses, each finding independently verified
by a skeptic before being accepted.

---

## What is done

- **Code repo** — 75 tests, 5 attack families, four-stream loop, sealed hash-verified audits
- **Walkthrough** — `docs/Walkthrough.docx`, generated from artifacts, never hand-edited
- **Dashboard** — `dashboard/index.html`, self-contained, no CDN, no server
- **Lane A** — real ULB data, verified against published spec (284,807 rows / 492 fraud)
- **LOFO zero-shot** — the headline claim, measured:

| Held out | Trained on | Recall | Realised FPR |
|---|---|---|---|
| F11 enumeration | F8 | **0.975** | 0.49% |
| F5 UPI push | F6 | **0.851** | 0.50% |
| F6 mule | F5 | 0.602 | 0.56% |
| F8 bust-out | F11 | 0.018 | 0.46% |
| F10 agentic | — | not defined (no agentic-rail sibling) | |

The asymmetry is the finding. A detector that only saw bust-out catches 97.5% of
enumeration it never saw; one that only saw enumeration misses bust-out almost entirely.

---

## The pitch, if it helps

Not "our detector catches fraud" — that claim is ordinary and our numbers are mixed.

**"A red-team lab whose distinguishing property is that it catches its own errors."**
`docs/FINDINGS.md` documents three retracted claims with the mechanism behind each, plus
defects caught before they produced a number. For a security audience that is a stronger
artifact than a clean curve, because everyone in that room knows the clean curves are
usually wrong.

**Submit on the morning of the 31st, not the night of.** Kaggle's rules state that
un-submitted draft work is not judged.
