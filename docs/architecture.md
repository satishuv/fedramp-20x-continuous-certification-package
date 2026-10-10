# Architecture

Two views: how a record gets built, and how it runs day to day.

## Document build flow

The shape of it first, then the exact dependencies.

```mermaid
flowchart LR
    DSU["CR26 rules dataset<br/>github.com/FedRAMP/rules"]
    SCU["Official SDR schemas<br/>fedramp.gov"]
    PIN["Pinned in this repo<br/>references/ and artifacts/schemas/official/<br/>sha256 compared every session"]
    RS["sdr/records/records-store.json<br/>168 rule entries, 46 indicator entries<br/>the security-decision facts you edit"]
    OP["profiles/common/offering-profile.json<br/>your identity, certification class,<br/>assessment and CPO inputs"]
    PIPE["Deterministic pipeline<br/>20 build steps, no network calls"]
    OUT["Deliverables<br/>SDR (JSON, extensions, text, Word, OSCAL),<br/>CPO, OCR, SCG, event artifacts,<br/>Rev 5 crosswalk, release manifest"]
    GATE["validate_sdr.py + validation gate<br/>schema, coverage, fidelity, CPO semantics,<br/>evidence integrity; gates the build"]
    SCAN["sdrscan.py<br/>38 checks, one finding per rule<br/>and per indicator, reports only"]
    SHIP["A package a reviewer can<br/>regenerate byte for byte"]

    DSU --> PIN
    SCU --> PIN
    PIN --> PIPE
    RS --> PIPE
    OP --> PIPE
    PIPE --> OUT
    OUT --> GATE
    OUT --> SCAN
    PIN -.->|re-resolves every statement, name and force| GATE
    GATE -->|0 hard failures| SHIP
    GATE -->|mismatch or hand-edited output| RS
    SCAN -->|what is still missing| RS

    classDef src fill:#e7f5ff,stroke:#1971c2,stroke-width:2px,color:#0b3d66
    classDef you fill:#fff4e6,stroke:#e8590c,stroke-width:2px,color:#7f2704
    classDef step fill:#f1f3f5,stroke:#495057,stroke-width:2px,color:#212529
    classDef out fill:#ebfbee,stroke:#2f9e44,stroke-width:2px,color:#14532d
    classDef gate fill:#fff0f6,stroke:#c2255c,stroke-width:2px,color:#7a1236
    classDef scan fill:#f3f0ff,stroke:#6741d9,stroke-width:2px,color:#3b1e7a
    class DSU,SCU,PIN src
    class RS,OP you
    class PIPE step
    class OUT,SHIP out
    class GATE gate
    class SCAN scan
```

Two inputs, one pipeline, two checkers with different jobs. The pinned dataset supplies every requirement statement, force level, family name, and class variant. The record store supplies your facts. Nothing else feeds a deliverable.

The dotted edge is the one worth staring at. The gate does not read what the pipeline produced and assume it is right; it goes back to the pinned dataset and derives the same answer independently.

Now the exact dependencies. This diagram shows the SDR-generation core; the full `build` runs 20 steps in dependency order (adding the CPO, OCR, SCG, event artifacts, OSCAL export, applicability ledger, assurance graph, and release manifest after the SDR is built - see [getting started](getting-started.md#running-the-steps-by-hand) for the complete list). Cylinders are files, rectangles are scripts, and the numbers are the order they run in:

```mermaid
flowchart LR
    DS[("references/<br/>CR26 dataset")]
    MAP[("traceability/<br/>aws-service-ksi-map.json<br/>curated, committed by hand")]
    RS[("sdr/records/<br/>records-store.json")]
    OP[("profiles/common/<br/>offering-profile.json")]

    B1["1 build_catalogs"]
    B2["2 build_notes"]
    B3["3 build_profiles"]
    B4["4 build_collector_registry"]
    B5["5 build_sdr"]
    B6["6 build_docx"]
    B7["7 build_crosswalk"]

    CAT[("rule-catalog.json<br/>ksi-catalog.json")]
    NOTE[("rule-notes.json<br/>ksi-notes.json<br/>family-names.json")]
    PROF[("class a, b, c profiles<br/>ksi-profile.json<br/>class D readiness register")]
    REG[("automation/collectors/<br/>registry.json")]
    JSN[("sdr/json/ official JSON<br/>plus extensions<br/>sdr/human-readable/ plain text")]
    DOC[("authoring Word file")]
    XW[("rev5-to-20x-crosswalk<br/>json and csv")]

    DS --> B1 --> CAT
    DS --> B2
    CAT --> B2 --> NOTE
    DS --> B3
    CAT --> B3 --> PROF
    MAP --> B4 --> REG
    PROF --> B5
    NOTE --> B5
    RS --> B5
    OP --> B5
    B5 --> JSN
    PROF --> B6
    NOTE --> B6
    RS --> B6
    OP --> B6
    B6 --> DOC
    CAT --> B7
    NOTE --> B7
    B7 --> XW

    classDef src fill:#e7f5ff,stroke:#1971c2,stroke-width:2px,color:#0b3d66
    classDef you fill:#fff4e6,stroke:#e8590c,stroke-width:2px,color:#7f2704
    classDef step fill:#f1f3f5,stroke:#495057,stroke-width:2px,color:#212529
    classDef mid fill:#e9ecef,stroke:#868e96,stroke-width:1px,color:#212529
    classDef out fill:#ebfbee,stroke:#2f9e44,stroke-width:2px,color:#14532d
    class DS src
    class MAP,RS,OP you
    class B1,B2,B3,B4,B5,B6,B7 step
    class CAT,NOTE,PROF mid
    class REG,JSN,DOC,XW out
```

Two things the arrows tell you that a numbered list hides. Step 4 depends on nothing upstream of it, only on the curated service map, so it can run at any point. Step 6 does not wait for step 5: the Word file is built from the same profiles, notes, and record store as the JSON rather than from the JSON, which is why `CDS-CSO-CBF` format consistency has to be checked rather than assumed.

`traceability/aws-service-ksi-map.json` is the one file in `traceability/` that is curated rather than generated. Everything else in that directory is a build output.

## Operational pipeline

Three loops run at different speeds: a change loop on every push, a daily evidence loop, and a daily currency loop watching FedRAMP itself.

```mermaid
flowchart TB
    subgraph change["The change loop, on every push"]
        direction LR
        DEVX["You edit<br/>records-store.json"] --> GIT["Push to your<br/>private repo"]
        GIT --> CI["CI gate<br/>regenerate, diff, validate, scan"]
        CI -->|0 hard failures| HUM["Named human<br/>reads the readiness report<br/>and approves"]
        CI -->|fail| DEVX
        HUM --> PUB["Published package<br/>versioned, encrypted<br/>backs a trust center"]
    end

    subgraph evidence["The evidence loop, daily"]
        direction LR
        COLL["Facts collector<br/>enumerated read-only AWS calls,<br/>refuses admin credentials"] --> EV["Evidence store<br/>timestamped facts,<br/>never committed"]
        EV --> READ["You read the facts<br/>and decide what<br/>they demonstrate"]
    end

    subgraph currency["The currency loop, daily"]
        direction LR
        DRIFT["Drift check<br/>sha256 of pinned sources<br/>against fedramp.gov"] -->|changed| ALERT["Issue or email:<br/>re-pin, rebuild,<br/>read the diff"]
    end

    READ -->|feeds tests and the SDR-CSX-KMT metrics clock| DEVX
    ALERT -->|a reworded rule may change your record| DEVX
    LLM["Layer 2, opt-in AI assist<br/>drafts prose from collected facts only"] -.->|proposes a diff, never a status| DEVX

    classDef you fill:#fff4e6,stroke:#e8590c,stroke-width:2px,color:#7f2704
    classDef step fill:#f1f3f5,stroke:#495057,stroke-width:2px,color:#212529
    classDef gate fill:#fff0f6,stroke:#c2255c,stroke-width:2px,color:#7a1236
    classDef out fill:#ebfbee,stroke:#2f9e44,stroke-width:2px,color:#14532d
    classDef plan fill:#f3f0ff,stroke:#6741d9,stroke-width:2px,color:#3b1e7a
    class DEVX,READ,HUM you
    class GIT,COLL,EV,DRIFT,ALERT step
    class CI gate
    class PUB out
    class LLM plan
```

Notice where the humans sit. Approval before publication, judgment between a collected fact and a written claim. Automation runs every edge that does not require a decision, and no edge that does.

## Why it is shaped this way

**Requirement text is resolved, never transcribed.** `build_catalogs.py` extracts every rule and indicator from the pinned dataset. If FedRAMP rewords a statement, the next build picks it up and the diff shows exactly what moved. Nobody retypes anything, so nobody introduces a subtle paraphrase that an assessor later reads differently than the rule intends.

**The validator does not trust the builders.** `validate_sdr.py` re-derives every statement, name, force level, and family expansion from the dataset through its own resolution path, then compares against what the builders produced. A bug in a builder cannot pass validation just because the validator shares its assumptions. This is the check that makes the traceability claim real rather than aspirational.

**Provider-owned inputs, enforced.** Continuous integration regenerates everything and fails if any generated file differs from what the pipeline produces. That converts "please do not hand-edit the outputs" from a convention into a build error.

**Determinism, deliberately.** Generated JSON, text, and CSV carry no run timestamps and are byte-identical across runs of unchanged inputs, verified by double-run hash comparison. Anyone can regenerate your package and confirm it matches what you shipped. Word files are the exception: their zip container embeds file-entry timestamps, so bytes differ while content is identical.

**Paths are relative.** Every script resolves paths from its own location, so the repository works from any checkout directory and in any continuous integration environment.

## The traversal problem, and why it is called out everywhere

The CR26 dataset nests rules five levels deep:

```
ds["FRR"][family]["data"][applicability][subset][rule_id]
```

`applicability` is one of `all`, `20x`, or `rev5`. An index built only from `data["all"]` silently drops every 20x-only rule, which is all of the `*-CSX-*` identifiers, including `FRC-CSX-VVK` and `FRC-CSX-VVR`, the two rules that motivate this entire framework. The failure mode is nasty: real rule identifiers appear fabricated, and a reviewer confidently reports a correct citation as an error.

The other three sections each use a different shape:

| Section | Shape | Count |
|---|---|---|
| `FRR` | `[family]["data"][applicability][subset][id]` | 245 entries; 233 in 20x scope, 12 rev5-only |
| `KSI` | `[family]["indicators"][id]`, no applicability layer | 46 indicators in 10 families |
| `CTL` | `[family][control-id]`, no applicability layer, holds `guidance` rather than `statement` | 79 entries in 14 control families |
| `FRD` | `["data"]["all"][id]`, keyed on `term` and `definition` | 80 definitions |

One resolver will not serve all four. FedRAMP documents this in its own `AGENTS.md`, and the repository mirrors that file so automated sessions read it before doing structural work.

## Repository layout

| Path | Contents |
|---|---|
| `references/` | Pinned CR26 dataset, hash-compared against upstream |
| `artifacts/schemas/official/` | Pinned official FedRAMP SDR and common-definitions schemas |
| `sdr/records/` | The single editable record store |
| `sdr/json/` | Generated official JSON plus extensions companion, per class |
| `sdr/human-readable/` | Generated plain text and authoring Word file, per class |
| `profiles/` | Per-class rule profiles, the common indicator profile, the offering profile, the Class D readiness register |
| `traceability/` | Derived catalogs, notes, family names, the Revision 5 crosswalk, the AWS service to indicator map |
| `validation/scripts/` | The pipeline and the validator |
| `validation/reports/` | Generated validation results, including per-indicator test results |
| `automation/collectors/` | Read-only facts collector and its registry |
| `automation/sdrscan/` | The readiness scanner |
| `automation/pipeline/` | Deployable AWS CodePipeline reference |
| `docs/` | This documentation |
| `.claude/` | Guardrails for automated agent sessions working in this repository |

`steering/` and `quality/` are local working notes, excluded by `.gitignore` because session logs carry engagement context.

## Design decisions worth questioning

Honest list of places where a reasonable person would choose differently.

**One giant record store.** A single JSON file with 214 entries is unwieldy in an editor and merges badly when two people work at once. Splitting per family would ease that at the cost of the single-editable-surface guarantee that everything else rests on. If concurrent authoring becomes the norm, this is the first thing to revisit.

**JSON rather than YAML for the record store.** YAML would be friendlier for long prose. JSON was chosen because the deliverable is JSON and the schema is JSON, so the authoring format matching the output format removes a translation layer where errors hide.

**Word output at all.** It exists because reviewers ask for it. It is also the one deliverable that cannot be byte-stable, which slightly weakens the reproducibility story.

**Python with three dependencies.** Deliberately boring, so a provider's security team can read the whole pipeline in an afternoon.

See [validation](validation.md) for what gets checked and [automation](automation.md) for the collector layers.
