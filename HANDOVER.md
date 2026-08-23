# Chakra — handover

**Repo:** https://github.com/N-45div/Chakra · **HEAD:** `89619ce` · 75 tests passing
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

The contract is **20 seeds × 10 generations × 5 families**. Current state:

| Family | Completed seeds | Registered target |
|---|---|---|
| F5  | 20 | 20 ✅ |
| F8  | 10 | 20 |
| F6  | 9  | 20 |
| F11 | 3  | 20 |
| F10 | 2  | 20 |

```bash
cd C:/Users/DivijN/chakra
./.venv/Scripts/python.exe scripts/run_registered.py --workers 4
```

Resumable and hash-keyed — safe to interrupt and restart. Any change to `chakra/`
invalidates prior directories automatically, so it will not silently reuse stale results.

**Then rebuild both artifacts:**

```bash
./.venv/Scripts/python.exe scripts/run_lofo.py
./.venv/Scripts/python.exe scripts/build_dashboard.py
./.venv/Scripts/python.exe scripts/build_walkthrough.py
git add -A && git commit -m "run: registered protocol complete" && git push
```

Render auto-redeploys on push.

---

## 5. Look at the rendered artifacts (I have not)

**This is the gap I'd fix first.** I verified the dashboard and walkthrough by grepping
markup and extracting text — I never viewed either rendered. For the artifact that decides
podiums, that isn't good enough.

- Open `dashboard/index.html` in a browser. Check both light and dark mode, chart label
  collisions, SVG geometry, the replay explorer scrubber.
- Open `docs/Walkthrough.docx` in Word. Check table overflow, page breaks, fonts.

---

## 6. Known issues worth your judgement

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

**A review workflow was mid-flight when I stopped.** Four lenses over the F8/F10/LOFO/
dashboard work, with skeptics verifying each finding. It never reported. Nothing from it
is incorporated. Re-run if you want that coverage.

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
