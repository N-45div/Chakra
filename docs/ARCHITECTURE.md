# Chakra — Architecture

End-to-end blueprint of the closed-loop adversarial fraud range. Component
diagrams in Mermaid; any PDF/docx renderer that supports Mermaid will show
them natively, and GitHub renders them in the repo view.

---

## 1. The system at a glance

One loop, three pillars, three data lanes. Everything else is machinery to
keep the loop honest.

```mermaid
flowchart LR
    subgraph Pillar1[Identify]
        TAX[13-family taxonomy]
        EXE[5 executable families<br/>F5 F6 F8 F10 F11]
    end
    subgraph Pillar2[Generate]
        GEN[Attack families<br/>parameterised raw-event emitters]
        SIM[Chakra simulator<br/>event ontology + background worlds]
        CAL[Lane C calibration<br/>NPCI/RBI aggregates]
    end
    subgraph Pillar3[Defend]
        DET[Detector<br/>LightGBM + IsoForest + logit baseline]
        LOOP[Four-stream adaptive loop<br/>feedback / training / monitor / audit]
        MET[Metrics<br/>AUPRC, recall@frozen cut, VWR, worst-family]
    end
    TAX --> EXE
    EXE --> GEN
    GEN -->|raw events only| SIM
    CAL -.constrains.-> SIM
    SIM -->|feature matrix| DET
    DET <-->|caught/missed| LOOP
    LOOP -->|mutated params| GEN
    LOOP --> MET
```

The red path is what makes it adversarial: the attacker consumes its own
failures. Detector → caught/missed → attacker mutates → generator emits →
detector retrains. Improvement is read on frozen monitor batches neither side
trained on.

## 2. One generation of the loop

```mermaid
sequenceDiagram
    participant P as Proposer
    participant G as Generator (family.emit)
    participant D as Detector
    participant C as Calibration stream
    participant F as Frozen monitor batch
    participant T as Training stream
    participant A as Locked audit (sealed once, never in loop)

    P->>G: parameter population
    G->>C: build stream (sized to 0.4% prevalence)
    C->>D: scores on legit rows only
    D-->>C: threshold frozen at 0.5% FPR
    G->>D: feedback world + attack episodes
    D-->>P: episode outcomes (yield before first alert, caught/missed)
    P->>P: fitness = gained - spent (rupees, both sides)
    P->>P: selection, mutation, crossover within bounds
    G->>F: monitor batch built once
    D->>F: score pre-retrain @ recalibrated cut
    G->>T: independent training stream
    D->>D: retrain
    D->>F: score post-retrain @ recalibrated cut
    Note over A,F: only F's pre/post delta is a claim
```

Five streams in four roles: calibration drives the threshold, feedback drives
the attacker, training drives the detector, monitor carries the improvement
claim, and the audit is scored exactly once at the end — sealed, hash-verified,
persisted before the loop starts.

## 3. Data lanes — never conflated

```mermaid
flowchart TB
    subgraph LaneA[Lane A — real data]
        IEEE[(IEEE-CIS card rows<br/>chronological split)]
        GENFIT[IEEE-compatible generator<br/>fitted on dev partition ONLY]
        TRTR[classifier trained on real]
        TSTR[classifier trained on synthetic]
        TEST[(identical locked<br/>labelled test partition)]
        IEEE --> GENFIT
        IEEE --> TRTR
        GENFIT --> TSTR
        TRTR --> TEST
        TSTR --> TEST
        TEST -->|TRTR vs TSTR gap| LARES[dataset-native synthetic utility]
    end
    subgraph LaneB[Lane B — Chakra simulator]
        FAM[5 attack families] --> SIM2[Indian payment event streams]
        SIM2 --> LOOP2[adaptive loop]
    end
    subgraph LaneC[Lane C — calibration]
        NPCI[(NPCI/RBI aggregates)]
        NPCI -.shapes distributions only.-> SIM2
    end
```

Lane A validates *dataset-native* synthetic utility and nothing about the
Indian families; it says so in the README, the deck and the walkthrough.

## 4. From attack idea to detector row

```mermaid
flowchart LR
    PARAM[AttackParams<br/>fraudster's knobs] -->|clamped to pre-registered bounds| FAM[Family.emit]
    FAM --> EVT[(raw events<br/>txn/auth/factor/mandate)]
    POP[Population<br/>consumers merchants agents devices] --> FAM
    FAM -.forbidden.-> FEAT[feature layer]
    EVT --> IDX[VisibilityIndex<br/>surface filter + available_at enforcement]
    IDX --> FEAT2[features<br/>velocity, fan-in/out, escalation, agent fan-out]
    FEAT2 --> MATRIX[(X, y, meta)]
    MATRIX --> DET2[detector] & THR[threshold calibration]
    DET2 --> SCORE[(score per decision row)]
    style EVT fill:none,stroke-dasharray:3 3
```

The forbidden edge is enforced by a test (`tests/test_no_feature_injection.py`)
so the detector learns fraud, never the generator's author.

## 5. Detector stack

```mermaid
flowchart TB
    X[(feature matrix)] --> GBM[LightGBM supervised head]
    X --> L1[Legit-only split] --> ISO[IsolationForest novelty head]
    X --> SCL[StandardScaler] --> LOG[LogisticRegression baseline]
    GBM --> COMB[combined score = supervised OR-lifted by novelty]
    ISO --> COMB
    LOG -->|reported alongside every figure| MET2[metrics]
    COMB --> THR2[operating cut frozen on calibration data]
    THR2 --> MET2
```

The novelty head exists to catch a share of a family the supervised head has
never seen — the LOFO narrative's second act. The baseline proves gains.
Thresholds are cut on calibration data at the target false-positive budget;
the *achieved* FPR is reported beside every recall.

## 6. Zero-shot (LOFO) protocol

```mermaid
flowchart TB
    RS[rail-scoped sibling sets] --> SY{sibling exists?}
    SY -- no --> NONE[no zero-shot number reported<br/>e.g. F10 on agentic]
    SY -- yes --> TR[train on sibling families<br/>fresh seeds]
    TR --> FIT[frozen detector]
    SIB2[sibling-only calibration stream] --> CUT2[cut frozen at 0.5% FPR]
    FIT --> EVAL[score held-out family<br/>fresh world, unseen seeds,<br/>full-bound parameter draws]
    CUT2 --> EVAL
    EVAL --> BNDL[AUPRC + recall@frozen cut + achieved FPR<br/>+ logit baseline]
```

The rail-scoping rule matters: a detector can only be held out from families
it could ever see on its own rail, otherwise the number measures rail mismatch
(FINDINGS F-004).

## 7. Experiment lifecycle — from contract to published number

```mermaid
flowchart TB
    CONTRACT[docs/EXPERIMENT_CONTRACT.md<br/>pre-registered: seeds, gens, metrics] --> RUNNER[scripts/run_registered.py<br/>5 families x 20 seeds x 10 gens, resumable]
    RUNNER --> DIR[runs/F_seedN_commit-hash/hash/]
    DIR --> GENJSON[generations.json]
    DIR --> INIT[audit parquets + manifest<br/>sealed BEFORE the loop]
    INIT --> SCORE[audit_score.json<br/>committed single look]
    GENJSON & SCORE --> DASH[scripts/build_dashboard.py<br/>-> dashboard/index.html static]
    GENJSON & SCORE --> DOCX[scripts/build_walkthrough.py<br/>-> docs/Walkthrough.docx]
    LOFO[scripts/run_lofo.py] --> LFOJ[runs/_lofo/lofo_results.json]
    LFOJ --> DASH & DOCX
    DASH --> RENDER[(Render static deploy<br/>buildCommand regenerates from artifacts)]
```

Run directories embed the code version hash so a score can never be attributed
to different source than the audit beside it. Dashboards and documents read
only these artifacts — a missing artifact renders as missing, never as a
placeholder number.

## 8. Web prototype (deployment shape)

```mermaid
flowchart LR
    REPO[(github.com/N-45div/Chakra<br/>JSON run artifacts ship<br/>parquet evidence stays local)] --> CI[GitHub Actions<br/>pytest 3.11/3.12]
    REPO --> RENDER2[Render static site]
    RENDER2 --> BUILD[build: python scripts/build_dashboard.py]
    BUILD --> HTML[static dashboard/index.html<br/>REPLAY explorer + report]
    HTML --> USER[judge opens page, scrubs generations]
```

Static by design: no server to cold-start, nothing that can fail in the room.
Recorded runs are labelled REPLAY on screen per the experiment contract.

## 9. Module map

```mermaid
graph TD
    subgraph package chakra
        SC[schema/] --- EV[events.py<br/>ontology + visibility]
        SC --- EN[entities.py]
        SC --- F[features.py<br/>registry + pipeline]
        GN[generate/] --- POPG[population.py]
        GN --- BG[background.py<br/>genuine traffic]
        GN --- CAL[calibration.py<br/>Lane C constants]
        GN --- AT[attacks/]
        AT --- F5[F5] & F6[F6] & F8[F8] & F10[F10] & F11[F11]
        DC[detect] --- DETX[detector.py]
        LP[loop] --- ORCH[orchestrator.py<br/>four streams]
        LP --- PROP[proposer.py<br/>evolution]
        EV2[evaluate/] --- M[metrics.py] & AUD[audit.py<br/>seal/claim/commit] & LF[lofo.py]
        LA[lanes] --- TSTR[tstr.py<br/>Lane A]
        GNL[generate layer] -->|events| F
        F -->|X,y,meta| DETX
        DETX -->|scores| LP
        PROP -->|params| AT
        AT -->|events| GNL
    end
    AT -. never imports .-> F
```

Dependency discipline in one picture: `generate/attacks` may build entities and
events, but the arrow to `schema/features` does not exist. Train, calibrate and
evaluate all read the same feature pipeline — the one that runs on real data.

## 10. Audit integrity state machine

```mermaid
stateDiagram-v2
    [*] --> Sealed: seal_audit - digest + parquets, before the loop
    Sealed --> Claimed: claim_scoring - verifies digest, reserves THE single look
    Claimed --> Committed: commit_scoring - scored.json written
    Committed --> [*]
    Sealed --> Failure: digest mismatch (tamper) - refuses
    Claimed --> Failure: no second look - raises
```

The audit stream is built once, scored once, and its digest is persisted
before any result exists — a judge can re-verify a published number without
trusting anything but the artifact it came from.