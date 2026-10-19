# Changelog

Notable changes to this project. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

One project-specific convention: the pinned FedRAMP dataset version is recorded alongside every release, because the same code against a different dataset produces a different record.

## Unreleased

Pinned dataset: `2026.10.13.01` (adopted 2026-10-14 in #223: 46 KSIs unchanged
in id, name, family and statement; 40 KSI NIST control lists changed, 0 rules
added or removed, 0 force changes; the AWS service-KSI map was re-verified by
diff against the previous dataset and its pin advanced)

### The last two Word-document exclusions are gone (AUD-F94)

- **AUD-F94 (Low).** `make reproducible` still diffed with `':(exclude)*.docx'`,
  and `build_release_attestation.py` excluded `*.docx` on all five of its git
  calls and told the operator so in five places, with the pre-AUD-F35 reason
  (zip timestamps) that no longer holds. Found by an external re-audit of main
  `ffb3b55` (2026-10-19), which named the Makefile; the attestation builder was
  the wider instance: `sdr.py release` would have attested a commit as the source
  of a package whose Word document had been hand-edited after that commit. Both
  now cover the whole tree, and every message says Word documents are inside
  the check.
- `test_docx_integrity.py` gains a structural test (no exclusion pathspec in
  either file, no "excluded" wording) and a behavioural one (append bytes to the
  tracked Class B `.docx`, the builder must report dirty naming it, restore
  byte-for-byte). Red-first: the behavioural test fails on the old builder, the
  structural one on the old Makefile; 10/10 after. MUT-F94 (the exclusion
  returns) killed.

### Release trust is anchored to protected main, not to the tagged commit (AUD-F91)

- **AUD-F91 (High).** The `verify-tag` job verified the tag's signature against
  `.github/release-allowed-signers` read from the tagged commit's own tree, and
  bound the tag only to `GITHUB_SHA`. Found by an external re-audit of main
  `ffb3b55` (2026-10-19) and reproduced in a throwaway clone: a side-branch
  commit carrying its own signer list, tagged and signed by that key, passed
  every check up to the manifest binding, and a passing run reaches the publish
  job's `contents: write`. The step now fetches `main` by its own ref (never from
  the tag) and requires the tagged commit to be an ancestor of it, failing closed
  naming the commit, BEFORE the signers file is consulted; so the signer list in
  force is one that passed `main`'s required `release-gate` check in a reviewed
  PR. Every AUD-F88 check follows unchanged. `docs/versioning.md` records
  `main`'s branch protection as part of the release trust chain. A `v*` tag
  ruleset (restrict creation, update and deletion) is a repository setting the
  owner applies beside this; it is recommended, not a substitute.
- `automation/pipeline/test_release_gate.py` section (g) holds the order and the
  fetch shape. Red-first: 104/110 on the old workflow (six new checks red),
  110/110 after. The shipped shell was executed verbatim under bash with real
  ssh-keygen keys: self-authorised side-branch tag refused at ancestry;
  attacker-signed tag on a main commit refused at `verify-tag`; listed-key tag
  on a main commit passed both and stopped only at the manifest binding, so a
  legitimate release is not over-blocked. MUT-F91 (ancestry becomes `if false`)
  killed.

### The living-SDR loop separates its cloud credential from its repository write (AUD-F89)

- **AUD-F89 (High).** `living-sdr-loop.yml` ran one job with `id-token: write`,
  `contents: write`, `pull-requests: write` and `issues: write`, assumed the
  AWS role, executed the collectors and the build, then pushed a branch and
  opened a PR in the same token scope. Found by an external review of main
  `23f46c9`. Now three jobs: `collect` holds the OIDC token with
  `contents: read` and hands the regenerated diff of tracked paths over as a
  patch artifact; `propose` holds `contents: write` and `pull-requests: write`,
  runs no AWS step, refuses a patch touching `.github/`, `audit/`, the
  dependency lock, the pinned sources, `profiles/common/` or any script, applies
  it with `git apply --index` and opens the PR; `alarm` holds `issues: write`
  alone. Workflow-level permissions are `contents: read`.
- New `automation/pipeline/test_living_sdr_privileges.py` asserts the separation
  from the parsed YAML (no job with both a token and a write; the AWS job
  read-only and pushing nothing; the writer without a token or AWS step; the
  diff crossing as an artifact). Red-first: 12 failures on the old workflow, 0
  after; the existing F29 to F32 loop assertions still pass. MUT-F89 killed.
### Lint telemetry and dependency-update automation, honest about their status (AUD-F90)

- **AUD-F90 (Medium).** No Ruff, Flake8 or Mypy configuration or CI step, no
  Dependabot schedule, and repository security updates disabled; Bandit was the
  only static analysis. Found by an external review of main `23f46c9`. Baseline
  measured before any configuration was written: Ruff's default rules report
  113 findings, the committed E/F/I/B/UP selection (E702 ignored as a deliberate
  test idiom, E402 per-file for tests) 166, of which 108 auto-fixable; every
  B023 and F841 hit was read and none is a defect. `ruff format --check` would
  reformat 197 of 202 files.
- New `pyproject.toml` with `[tool.ruff]` only (no packaging tables; the repo
  runs from a checkout) and the baseline recorded beside the rule selection. New
  `quality` job in `validate.yml`: `ruff check` and `ruff format --check`,
  report-only (`continue-on-error`, with `set -o pipefail` so the step shows its
  real status), reports uploaded, deliberately outside `release-gate`. New
  `.github/dependabot.yml`: weekly pip and github-actions updates, with the note
  that an input bump needs `make lock` before the hashed CI sees it.
- Coverage was NOT added: the suite spawns a Python subprocess per gate, so a
  meaningful number needs subprocess-aware wiring and a measured baseline first.
- `validation/scripts/test_quality_telemetry.py` holds the pieces to what they
  claim (report-only, outside the gate, pinned, scheduled). Red-first: 11
  failures with the pieces absent, 0 after. MUT-F90 (the lint step silently
  becomes a hard gate) killed.

### Documentation facts are now derived and tested, not hand-synced (AUD-F86)

An external security and maintainability review of main `23f46c9` (2026-10-18)
found the README still advertising the previous dataset release five days after
the pin advanced, and the architecture guide still calling Word output the
exception to byte determinism five months after AUD-F35 removed the exception.
Re-reading every document against the dataset on disk widened it to seven files.

- **AUD-F86 (Medium).** The README badge, pin sentence and derived-counts
  sentence said `2026.10.08.01`; `docs/automation.md` and `docs/comparison.md`
  claimed `2026.09.13.02` as the current pin; the dataset, `sources.lock.json`
  and the profiles all carried `2026.10.13.01`. The counts themselves (233 of
  245 rules in 20x scope, 12 rev5-only, 46 KSIs in 10 families) were still
  right. `docs/architecture.md`, `docs/validation.md` and `docs/versioning.md`
  still said Word files are not byte-stable while `docs/faq.md`,
  `docs/getting-started.md` and the CI double-build (which hashes `*.docx`)
  said the opposite. `docs/versioning.md` said CI installs
  `requirements-ci.txt`; every CI path installs `requirements.lock` with
  `--require-hashes`. The `validate_sdr.py` comment on `dataset_version_agreement`
  promised the README and badge were covered; the check reads the dataset and
  the profiles only. All seven documents corrected; the comment now says what
  the check reads.
- New `validation/scripts/test_docs_facts.py`, in the offline suite: derives the
  version, the FRR counts by applicability and the KSI counts from the dataset
  by its real nesting, holds every sentence that claims the current pin to that
  version, holds the README counts to the derived counts, and refuses the stale
  Word-exception phrasings. Historical references (release tag examples, the
  changelog) are not pin claims and are not checked. Red-first: 8 failures on
  the unmodified tree, 0 after. MUT-F86 (badge reverted to the previous
  release) killed.
### Onboarding checks installed versions against the pins (AUD-F87)

- **AUD-F87 (Medium).** `setup.py` answered "all present" from `__import__` of
  five module names, so any installed version passed as the pinned one and the
  install step never ran; the first run of the corrected check on the
  development interpreter found `cryptography` 46.0.3 installed against the pin
  50.0.2. It now reads the pins from `requirements.txt` (no second list; the
  dead `DEPS` is gone), reads each installed distribution's version through
  `importlib.metadata`, reports every absent or differing distribution as
  (installed, pinned), installs the pinned set on any mismatch and fails closed
  if a mismatch survives. Found by an external review of main `23f46c9`.
- The review's proposed remedy, `requirements.lock --require-hashes` as the
  default install, was tested and not adopted: the lock is resolved for Linux
  and Python 3.12, carries the CI-only CDK tooling, and does not install on
  Python 3.10 (`rpds-py==2026.6.3` requires 3.11+), while the repository
  promises 3.10+ and `requirements.txt` resolves there. The docs now name both
  paths with their scope, `docs/getting-started.md` says five packages (it said
  three), and `make install-locked` installs the hashed closure.
- `test_install_dependencies.py`: new `test_setup_checks_installed_versions_against_pins`
  (injected oracle: one pinned, one wrong, one absent) and the F-08 guard
  retargeted to the single-source reader. Red-first; MUT-F87 killed.
### Release tags are verified cryptographically against a committed signer list (AUD-F88)

- **AUD-F88 (High).** `release.yml` checked only that the tag object contained
  a `BEGIN (PGP|SSH) SIGNATURE` block and said so in its header; a tag signed
  by any key passed, and nothing bound the tag to the commit the run built.
  Found by an external review of main `23f46c9`. The maintainer's practice was
  read from the tags themselves: v1.5.0 and v1.6.0 are SSH-signed by one
  ed25519 key (fingerprint `SHA256:95T8oBQ46qClD/NUDTlUsP6hxVKCLDsfjMJtsZY5wAY`),
  extracted from the signature blobs and matched to the configured public
  signing key.
- New `.github/release-allowed-signers` holds that public key in ssh-keygen
  `allowed_signers` form, with the rotation procedure in its header; no private
  key enters the repository. The verify-tag job now sets `gpg.format=ssh` and
  `gpg.ssh.allowedSignersFile` to it, refuses a signers file listing no signer,
  runs `git verify-tag` (fails on no signature, an invalid signature, or a valid
  signature from an unlisted key), requires the tag to resolve to `GITHUB_SHA`,
  and keeps the manifest `release_tag` binding. `docs/versioning.md` describes
  verification, the consumer command and key rotation.
- `test_release_gate.py` section (f): six new checks, red-first (99/104 with the
  old workflow, 104/104 after). The shipped shell was executed verbatim under
  bash against the real tags: wrong `GITHUB_SHA`, unsigned tag, empty signers
  file, unlisted key and manifest mismatch each fail closed; v1.5.0 and v1.6.0
  verify against the committed file. MUT-F88 killed.

### First live AWS collection: four defects the fixtures could not see (AUD-F82 to AUD-F85)

The read-only collectors ran for the first time against a real account (one
AWS Organizations management account with Control Tower, Config, Security Hub,
GuardDuty, Inspector and Access Analyzer active) under a role granting exactly
`READ_ONLY_ACTIONS`, and the facts went through prefill and the metric appender.

- **AUD-F82 (High).** `append_metrics.py` recorded 0 KSIs from 36 fresh posture
  facts and exited 4: the freshness predicate looked each check-scoped
  allowlist key (`ec2:security_groups`, AUD-F16) up in a map keyed by the bare
  service, so no posture-only KSI was ever fresh and the SDR-CSX-KMT history
  could not advance from a live run. It now resolves the key exactly as routing
  does. Same facts store afterwards: exit 0, 13 KSIs appended. Three
  regressions, MUT-F82 killed.
- **AUD-F83 (Medium).** Three collectors were denied under the repository's own
  role because four allowlist entries were spelled as boto3 names, not IAM
  action names: `access-analyzer:` is the prefix IAM evaluates, and the S3
  actions are `GetEncryptionConfiguration` and `GetLifecycleConfiguration`.
  The deployable `CollectorRole` carried the same strings, and the parity
  test's regex excluded hyphenated prefixes, so the two copies agreed with
  each other. Both fixed; the regression checks every prefix against
  botocore's signing names, an oracle independent of the allowlist. MUT-F83
  killed.

- **AUD-F84 (High).** All 34 registry Config managed rules read
  `RULE_NOT_DEPLOYED` while the account ran 29 of them under Security Hub
  (`securityhub-<rule>-<hash>`) and conformance-pack
  (`<rule>-conformance-pack-<id>`) names: the live collector queried the exact
  catalog name only. The offline importer already resolved deployed names
  (exact id, the Security Hub shape, `Source.SourceIdentifier` through the
  pinned vocabulary); that logic now lives in
  `automation/collectors/config_rule_resolution.py`, shared by both paths.
  The collector lists the account's rules once (`config:DescribeConfigRules`,
  a read verb added to the allowlist and the `CollectorRole`), queries every
  deployed instance and aggregates worst-wins, recording `instances`,
  `deployed_names` and the `resolution` mode on each fact. A role without the
  new grant falls back to the exact name and every fact says
  `exact-name-only`. 26 checks, 5 red against the old collector, MUT-F84
  killed.
- **AUD-F85 (High).** The multi-account fan-out, the repository's only width
  lever for an AWS Organization, produced facts no metric ever saw. Run across
  the management account and one member account it iterated only the 36
  posture collectors (the 34 registry Config rule checks lived inline in
  `collect_facts.py main()`) and wrote one flat list to `multi-account.json`,
  a name outside the `facts-*.json` glob every downstream reader opens. The
  per-scope Config rule unit is now `collect_facts.collect_config_rule_facts`,
  called by both drivers (a denied listing degrades to `exact-name-only` for
  that scope only); the fan-out writes `facts-multi-account.json` in the
  `{meta, facts, posture_facts}` shape with its own `collection_outcome`, and
  refuses an `--out` name the pipeline would not read. Reading the two stores
  together then exposed the second half: the management account's facts
  carried no account tag in the single-account store and did in the fan-out's,
  so `load_facts` saw two scopes and every one of 28 routed indicators doubled
  (KSI-CMT-LMC 3/3 became 6/6; KSI-IAM-JIT 141/143 became 282/286). The loader
  now derives a store's account from `meta.identity_arn` and applies it to
  untagged facts, so one scope is one observation. Live afterwards: 71 facts
  over 2 accounts (34 rules checked, 29 deployed) and every indicator back at
  its single-store value. 18 checks plus one appender regression, both red
  first; MUT-F85 killed, and three further hand mutations (loader de-dup, store
  name, store shape) each turned their guarding check red.

### Implementation guidance notes for Google Cloud, Microsoft Azure and Oracle Cloud Infrastructure (MCE-17)

The how-to-comply notes layer described AWS only (MCE-16 labelled it so). A
provider on another platform now selects its own notes with one profile field,
`guidance_platform`: absent or `AWS` keeps the built-in notes and produces the
committed artifacts byte for byte; `Google Cloud`, `Microsoft Azure` or
`Oracle Cloud Infrastructure` selects a data file under `guidance/platforms/`
(46 KSI notes each, plus overrides for the four FRR families whose built-in
text names an AWS service: CMU, IEC, MAS, VDR; the other thirteen families use
a neutral base that names no platform). Each file records the date its
service names and documentation URLs were captured from the vendor's public
documentation and a `services` table; the build adds `guidance_references`
(the vendor URL for every service a note names) to each note and records the
sources at the top of `traceability/rule-notes.json` and `ksi-notes.json`. An
unknown label fails the build and lists the platforms available; the notes
layer never substitutes AWS guidance for another platform (fail closed by
design, proven red by hand). The fictional non-AWS Class C sample declares
`Google Cloud` and reaches READY with its extension, records store and DOCX
labelled "Google Cloud implementation examples".

Built to be removable: every third-party name lives in a file that exists only
for it plus one registration row and one watchlist line, and
`THIRD_PARTY_NOTICE.md` gains a "Removing a third party" procedure backed by a
new read-only `--inventory` mode of the naming guard that lists, per registered
name, the tracked files that still contain it (computed from the tree, never
maintained by hand). The 87 service names the notes introduce are registered per
owner (the guard now registers 102 names, 15 before) and added to the guard's watchlist, so every sentence naming one is
checked for comparative or evaluative language; a `validation/scripts/test_platform_guidance_notes.py`
suite (57 checks) additionally requires each platform file to be complete
(every KSI, every AWS-specific family, every service registered and used), and
every note to carry no AWS service name, no lexicon term even where no vendor
is named, no compliance-determination verb, no URL and no em or en dash. Four
by-hand mutations (fail-open to AWS, a dropped family override, an evaluative
sentence, an AWS name inside a Google Cloud note) each turn exactly the
intended check red. Documented in `guidance/platforms/README.md`,
`docs/getting-started.md` and the non-AWS quickstart.

### Provider quickstart for a platform other than AWS (MCE-14)

`docs/quickstart-non-aws.md` walks a provider from an export its tooling
already writes, through a mapping, the facts in the one contract, hashed
evidence with bound pointers, a signer pinned by label, to `package-preflight`
READY, with every fenced command runnable offline against the committed
fixtures and no credential anywhere. The new
`validation/scripts/test_quickstart_non_aws.py` makes it executable
documentation: it runs every `bash` fence from the repository root and
requires exit 0 (the three mapping dry runs print facts and a collected
outcome, the conformance suite reports 0 problems, the non-AWS sample reports
READY under production-assurance), checks that every repository path the
document names exists, that the files the sample overwrites are restored byte
for byte, that no fence carries an access-key-looking token or a literal
secret, that the scope key is shown as a placeholder, and that the document
states its outputs are expectations and readiness findings, never compliance
determinations. Linked from the documentation index. Closes the multi-cloud
evidence epic's last story.

### Fictional non-AWS Class C sample through READY and the attack harness (MCE-12; AUD-F81)

`examples/sample-offering-class-c-non-aws`: a fictional provider hosted on
Google Cloud with on-premises XCCDF scans, driven to Submission ready under
`production-assurance` with every evidence entry behind every populated KSI
coming through the ADAPTER PATH a real provider uses. The profile enables
three mapping-driven sources (the Security Command Center and XCCDF reference
mappings, and a new `example-provider-collector` reference mapping that
declares the provider's own collector the same way, one check per KSI the
posture sources do not bind, so first-party and third-party evidence meet one
binding rule); `apply_sources` attaches 55 entries to the 46 KSIs by declared
binding; every entry is hashed and signed by a stand-in managed key pinned by
label (`key_reference`); the profile declares no AWS platform, so the gate
binds only those three sources. The exports are produced in memory from the
committed fixtures with today's observation times and exist on disk only for
the apply step; the sample fails if the folder outlives a run. The AWS Class C
harness's `attack()` is now parametrized by a `SamplePlatform` (AWS the
default, behaviour proven identical: 52 probes with the same names, kinds,
pins and tamper digests before and after the change); the non-AWS sample runs
the same 48 shared probes with the same gate pinned per probe plus four of its
own (an adapter fact re-pointed at a KSI its source does not bind, blocked by
the provenance gate; a signed AWS Config-rule claim the offering cannot make,
blocked, AUD-F79; a populated KSI stripped of evidence, blocked by the
validation gate; the same adapter entry under the second KSI its check binds,
READY). New `validation/scripts/test_attack_harness_probes.py` pins both
probe lists against `examples/sample-offering-class-c/attack-probes.golden.json`
and asserts the shared probes are identical across platforms (AC2). The
harness is the new `attack-non-aws` section of the one release gate: CI runs
it as `attack-gate-non-aws` in parallel with `attack-gate`, the aggregate
requires it, and the AWS build and `sdr.py release` run it. `AUD-F81`
(Medium), found by the sample's first dry run: the AUD-F63 pointer check
predated the AUD-F77 per-record pointer segment, so every entry from a source
that reports one record per resource (all 11 Security Command Center entries
here) was pointer-unbound and production-assurance was unsatisfiable for such
a source; `classify_pointer_binding` now mirrors the factory's form, the
SOURCE family of `test_provenance_mutations.py` carries a per-record pointer
(bound), a pointer moved to another record (unbound) and a record segment
stripped (unbound), red on the pre-fix classifier; `MUT-F81` killed.

### Evidence sources scoped to the offering, and concrete adapter pointers (MCE-12 groundwork; AUD-F79, AUD-F80)

Found while designing the non-AWS Class C sample (MCE-12). `AUD-F79`
(Medium): the provenance gate built its bindings from everything the
repository knows (the AWS collector registry, the Config-rules manifest, every
adapter registered in the process) and never read the offering profile, so an
offering with no AWS platform could attach a valid, signed entry claiming an
AWS Config rule it never ran and pass the AUD-F62 check, and any offering
could claim a registered adapter's declared pair while its profile said that
source was disabled; the AWS Class C sample itself relied on the second path.
Now `validate_evidence.load_source_bindings` takes the offering profile (the
preflight passes the one it loaded, the validator and the MAS builder
likewise): the registry and the manifest bind only for an offering that
declares an AWS platform (`aws_partition`, the MCE-16 predicate), and a
registered adapter binds only when `evidence_sources` enables it. The unbound
messages say the source is not one this offering operates. The signer pin
accepts the neutral `key_reference` beside the AWS `key_arn`. The AWS Class C
sample now enables the Falcon source its MCE-03 probes claim, reads its
bindings under its own profile, and gains a probe attaching a disabled
adapter's declared pair under that adapter's own target (blocked by the
provenance gate; it reaches READY on the unfixed gate). `AUD-F80` (Medium):
the adapter apply path never supplied an evidence location base, so every
adapter-derived pointer was an `sdr://placeholder/` pseudo-URI that
`package-preflight` refuses at Class C, while the collector path honours
`SDR_EVIDENCE_LOCATION_BASE`; a provider on any platform following the adapter
path could never produce a Class C ready entry. `apply_third_party_evidence.py`
now exposes `apply_sources` (the whole attachment logic over an injected
profile and store, writing nothing) and its CLI reads `--location-base`
(default `$SDR_EVIDENCE_LOCATION_BASE`) and prints one note when attaching
placeholders. New `validation/scripts/test_offering_scoped_sources.py` (34
checks, red on the pre-change engine); the MCE-03, provenance-mutation and MAS
tests read bindings under a profile that enables Falcon and assert the
committed template binds no adapter pair. `MUT-F79` (every offering binds the
AWS sources) and `MUT-F80` (the base dropped from the adapter path) killed;
the enabled filter removed by hand fails the regression and lets the sample's
new probe reach READY.

### Platform-labelled implementation notes and optional AWS metadata (MCE-16; AUD-F78)

Sequenced before the non-AWS Class C sample (MCE-12), because a non-AWS
package cannot honestly declare `aws_partition`. `AUD-F78` (Medium): every
how-to-comply note the notes layer authors describes AWS implementation
approaches (15 of 46 KSI notes name an AWS product outright), and the notes
carried that fact only in a free-text label that the SDR extension, the
records store's `fill_guidance` and the DOCX did not copy, so a provider on
another platform met AWS implementation steps presented as how to comply with
no statement of which platform they describe or that they are not the
provider's own words; separately, the extension, the human-readable SDR and
the DOCX read `aws_partition`, `primary_region` and `dr_region` with
`profile[...]` and failed with a `KeyError` on a profile without them, which
the profile contract allows. Now `build_notes` stamps a structured
`guidance_platform` (`AWS`) on every rule and KSI note; `build_extensions`
copies it as `how_to_comply_platform` beside every `how_to_comply` and the
guidance note names the platform and says the text is not the provider's own
statement (the platform is read from the note, never from the profile, so a
non-AWS package still labels AWS guidance as AWS); the records store's
`fill_guidance` carries the same member; the DOCX label reads "How to comply
(SAS guidance, AWS implementation examples, not the provider's statement)";
the platform metadata members and header lines are emitted only when the
profile declares them (`regions` only when both region fields are present),
and a profile that declares them yields the same members in the same order.
All three classes' extensions, the records store and the three DOCX files
regenerated; the official SDR JSON did not move. Regression:
`validation/scripts/test_platform_labelled_notes.py` (red on the pre-change
builders), registered in the validate suite; MUT-F78 (the note stops naming
the platform) killed. `docs/faq.md` states both behaviours.

### Adapter conformance suite, traceability and MAS coverage (MCE-13)

Three closures of the adapter layer, no production path changed. (1)
`automation/collectors/test_adapter_conformance.py`, in the validate suite,
proves every evidence adapter by discovery: every mapping fixture under
`fixtures/mapping` must have an export and a golden expected-facts file and
must reproduce the golden byte for byte offline, with every fact meeting the
contract, every bound KSI in the pinned profile, a documentation citation for
a third-party source and every declared check bound to a KSI; every Python
adapter `thirdparty_adapters` registers must have a golden case and reproduce
it; a fixture or adapter without a golden fails naming it, so a source cannot
be added without conformance. Its first run found that the `csv-count`
reference adapter declared no checks and said nothing about it; it now
declares `illustrative = True`, which the suite reports, and the provenance
gate's treatment of its evidence as unbound is stated in its docstring rather
than implied. Baseline: 5 mapping fixtures and 3 Python adapters, 0 problems;
a tampered golden goes red naming the first differing fact. (2) Every adapter
is a gate `adapter.<name>` in `traceability/rule-test-map.json` (mode
`evidence-adapter`) with its declared checks, the KSIs its source bindings
target, the validate-suite tests whose source names it and the runner
mutations those tests kill, joined deterministically; only a source the
offering profile enables contributes per-KSI entries, so the eight new gates
leave the coverage figure unchanged (Class C still 21 of 203) instead of
letting example fixtures inflate it. `test_rule_test_map.py` checks every
adapter gate's tests, mutations and KSI targets resolve, that
`enabled_in_profile` mirrors the profile, that no disabled source contributes
an entry, and that enabling one makes it, and only it, count. (3) The MAS
coverage report accepts a `service:check` reference to adapter-sourced
evidence (the opaque pointer of such an entry is not something a person
writes): it resolves only when such evidence sits in that KSI's record and
the source registry binds the pair to that KSI, the same binding the
provenance gate enforces, otherwise the cell is unresolved naming the pair; a
resource of a non-AWS kind with no `aws_service` is classified by the same
rules without raising. Both new test blocks were run red against the
pre-change builders. Docs: `docs/validation.md` and the evidence-sources
README.

### Oracle Cloud Infrastructure Cloud Guard problems adapter (MCE-06)

The third cloud source outside AWS, through the mapping-driven adapter and one
reference mapping (`example-oci-cloud-guard.mapping.json`), no Python and no
engine change. Records have the published `ProblemSummary` shape (a
`ProblemCollection` `items` array), read from the fixture envelope or a bare
array. The state is read from `lifecycleDetail`, the published substate: only
`OPEN` is `FAIL`; `RESOLVED`, `DISMISSED` and `DELETED` are `UNKNOWN`, never
`PASS`, with the substate kept in `detail`, because a problems export states
no pass; a substate outside the published enum is `UNKNOWN`; the coarse
`lifecycleState` (`ACTIVE`, `INACTIVE`) is never read (a record whose state
contradicts its substate follows the substate). The problem `id` is the
per-record identity (AUD-F77 applied: two problems of one detector rule in one
compartment and region keep distinct pointers, and dropping `record_id`
collapses the batch to the collision refusal); the compartment OCID is a
`compartment` scope; neither reaches an evidence object. The first entry of
`regions` is the location (the single `region` field is documented as
deprecated); a problem with no region lands in `global`. Field names and the
wire values come from the owner's published SDK model reference and enum
sources, cited with capture dates in the fixture header and the mapping; the
fixture is fictional end to end (OCIDs of the form
`ocid1.<type>.oc1..fictional<counter>`, `fictional-` names, `FICTIONAL_`
detector rules). Regression: `automation/collectors/test_oci_cloud_guard_adapter.py`
(12 checks; the fixture mutation relabelling `RESOLVED` as `PASS` goes red),
registered in the validate suite. `THIRD_PARTY_NOTICE.md` moves the Oracle row
from planned to present; the evidence-sources README documents the mapping.
With this entry all four non-AWS sources of the epic (MCE-04 to MCE-07) are
present.

### Microsoft Azure Policy compliance-states adapter (MCE-05)

The second cloud source outside AWS, through the mapping-driven adapter and
one reference mapping (`example-azure-policy-states.mapping.json`), no Python.
Records have the Policy Insights REST API's published `PolicyState` shape (the
`queryResults` response, a `value` array), read from the fixture envelope or a
bare array; the state is read from the documented `complianceState` field, and
the `isCompliant` flag, which the owner documents as deprecated, is never
read (a record whose flag contradicts its state follows the state). Only
`Compliant` is `PASS` and only `NonCompliant` is `FAIL`; `Exempt` and
`Conflict` are `UNKNOWN`, and every other published state (`Error`,
`Protected`, `Unknown`, `Not registered`, `Not started`) is `UNKNOWN` by the
unmapped rule, never `PASS`, with the state kept in `detail`. The shape and
vocabulary come from the owner's public API reference, compliance-states page
and sample queries, cited with capture dates in the fixture header and the
mapping; the fixture is fictional end to end (the all-zero subscription id,
all-zero and all-one definition and assignment ids, `fictional-` names). One
engine addition, needed because a policy state has no single id field: a
mapping's `fields.record_id` may be an ordered list of paths forming a
composite identity (`composite_record_id`, pure), joined with `|`, an absent
component kept as an empty string so components keep their positions and two
different identities can never join to the same string; proven by hand (the
dropping variant goes red on the position check). The composite for a policy
state is assignment, definition, reference id and resource, the grouping the
owner's own sample queries use, so the two states of one definition on one
resource under two assignments keep distinct pointers, and dropping
`record_id` collapses the batch to the AUD-F77 pointer-collision refusal.
Regression: `automation/collectors/test_azure_policy_adapter.py` (15 checks,
red on the pre-change schema), registered in the validate suite.
`THIRD_PARTY_NOTICE.md` moves the Microsoft Azure row from planned to present;
the evidence-sources README documents the composite identity.

### Google Cloud Security Command Center findings adapter (MCE-04; AUD-F77)

The first cloud findings source outside AWS, through the mapping-driven
adapter and one reference mapping (`example-google-cloud-scc.mapping.json`),
no Python. Records have the published `ListFindingsResult` shape (a `finding`
and a `resource` object, the form the command-line listing prints), read from
either the fixture envelope or a bare array; the states are the published
`Finding.State` enum: `ACTIVE` is a problem the source still reports (`FAIL`),
`INACTIVE` covers a fixed finding and one a person closed as not an issue,
which the export cannot tell apart, so it is `UNKNOWN` with the state kept in
`detail`, never `PASS`; a muted `ACTIVE` finding stays `FAIL`; a state outside
the enum is `UNKNOWN`. The shape comes from the owner's public API reference,
cited with capture dates in the fixture header and the mapping; the fixture is
fictional end to end (all-zero organization and source numbers, `fictional-`
project names). Building it exposed one defect, reproduced against the
unmodified engine before anything was changed. `AUD-F77` (High): a findings
export carries one record per resource, while the evidence pointer was derived
from service, check, opaque scope and region only, so two findings of one
category in one project and region resolved to one pointer and the record
store, which keeps one entry per pointer, kept only the later observation: a
resolved finding replaced a still-active one and the package showed nothing
wrong. The fact contract now carries `record_id` (the source's own identity for
one record) and the mapping schema `fields.record_id`; `fact_to_evidence`
derives an opaque `record` from it as an HMAC under the deployment scope key
(`record_ref`, keyed like the scope id because a finding name embeds the
organization id and an unkeyed digest of a low-entropy name is brute-forceable),
appends it to the pointer after the region, stamps it on the sanitized source
fact and never exports the raw id; a raw `record_id` with no scope key is
refused naming the field, and a caller-stamped record that is not an opaque
`rec-` id is refused. `EvidenceAdapter.to_evidence` refuses any batch in which
two facts resolve to one pointer, naming the pointer and the `record_id`
remedy, through the new pure `pointer_collisions`. The same finding keeps the
same pointer across exports, so a later observation replaces the earlier one
while two findings never share a pointer; the AWS pointer form is unchanged
when no `record_id` is present, so no committed artifact moved. Regression:
`automation/collectors/test_scc_adapter.py` (16 checks, red on the pre-change
engine), registered in the validate suite; MUT-F77 (collision refusal
disabled) killed in the runner, the keyed-id guarantee proven red by hand
(unkeyed digest fails the two-keys-two-ids check). `THIRD_PARTY_NOTICE.md`
moves the Google Cloud row from planned to present; the evidence-sources README
gains the per-record section and the two contract fields.

### On-premises XCCDF results adapter (MCE-07; AUD-F75, AUD-F76)

A provider with no cloud turns a benchmark scan into KSI-bound facts through
the mapping-driven adapter: `"export_format": "xccdf"` reads an XCCDF 1.1 or
1.2 results document or an ARF result data stream (what an OpenSCAP scan
writes) through the new `automation/collectors/xccdf_reader.py`, one record
per `rule-result`, with the rule id as the check, the `TestResult` end time as
the fallback observation time (never invented), DOCTYPE refused, and the
`TestResult` matched by namespace and local name wherever it sits so one code
path reads both output forms. The format is grounded in the NIST XCCDF 1.2
schema and the OpenSCAP user manual, both cited with capture dates in the
fixture header and the mapping; the fixture is fictional end to end. Building
it exposed two defects. `AUD-F76` (High): the XCCDF result vocabulary is the
standard's, not a vendor's, yet the generic mapping path let a provider table
relabel `notchecked`, `error` or `fixed` (defined by the standard as "had
failed, but was then fixed", no re-check implied) as `PASS`, or omit `fail`
so failures read as `UNKNOWN`. Now only `pass` is `PASS` and only `fail` is
`FAIL`, the other seven values are `UNKNOWN`, a table that relabels or
misspells a standard value is refused naming the key, and the standard's full
table applies regardless of what the mapping lists. The same story added an
explicit `undeclared_checks` policy to the mapping schema (`refuse`, the MCE-02
default, or `skip`): a benchmark scan reports every rule in the benchmark, and
under `skip` an unbound rule yields no fact and is counted and named in the
adapter's health record and by the apply driver, never exported unbound and
never silent. `AUD-F75` (Medium): the fact contract's raw-scope list had no
kind for a scan target, so a host-keyed fact would have been exported with
its hostname silently dropped and every host sharing one pointer (the AUD-F27
collision) instead of being refused without a scope key. `host` is now a raw
scope kind in the contract and the mapping schema; `scope_id` derives
`host:<name>` under the deployment key, so a host never shares a scope with
an account of equal literal, and the reader never copies the target into a
record's summary. Regression: `automation/collectors/test_xccdf_adapter.py`
(18 checks: AC1 one fact per declared rule-result offline, ARF and 1.1 forms
identical; AC2 every non-pass value UNKNOWN and relabelling refused; AC3 host
only through the scope path, no host name or address in any evidence object;
AC4 golden fixture byte for byte with the documentation header; the apply
driver end to end, attaching each rule to exactly its declared KSIs) and the
fact-contract test's raw-scope set. Mutations `MUT-F75` (host leaves the
contract) and `MUT-F76` (relabelled standard values accepted) are killed.
`THIRD_PARTY_NOTICE.md` updates the OpenSCAP row from a planned adapter to a
present one; `examples/evidence-sources/README.md` gains the on-premises section.

### Pluggable signer contract, KMS as one implementation (MCE-08; AUD-F74)

`automation/collectors/signers.py` defines one signer contract
(`sign(content_hash) -> xEvidenceSignature`) with three implementations:
`KmsSigner` (the existing AWS path, delegating to `sign_hash` unchanged, same
KMS call, same block, key id never the ARN), `ExternalCommandSigner` (a
separately administered signing service behind an operator-supplied command
that receives ONLY the canonical hash on stdin and returns the ECDSA P-256
signature; non-zero exit, empty or non-base64 output fail closed) and
`SoftwareKeySigner` (a PEM key, development and fixtures). The verifier is
unchanged: `validate_evidence.py` has no signer branch, and a software- or
externally-signed entry classifies `verified` under the pinned key through the
same offline path as KMS. Non-KMS key references are labels checked by shape:
an ARN, a URL or path, any 12-digit run or any GUID (a tenant, subscription,
compartment or project identifier) is refused before a block exists, because
the downstream `no_sensitive_patterns` gate cannot tell a tenant GUID from the
KMS key id the AWS path legitimately records. Building this exposed `AUD-F74`
(Medium): the profile pinned the verifier key but declared nothing about who
administers the signing key, so a PEM key held by the collecting pipeline
could sign under a production-assurance declaration of a separately
administered signer and preflight could not tell. New
`expected_evidence_signer.signer_kind` (`managed-key-service`,
`external-command`, `software-key`; neutral names); `package-preflight` warns
when undeclared, blocks an unknown value under both profiles, and blocks
`software-key` under production-assurance naming the signer as not separately
administered. The Class C sample declares its fictional signer and gains one
attack probe (51 probes). Regression `automation/collectors/test_signers.py`
(in the validate suite), red on the pre-change tree; `MUT-F74` killed; the
GUID-refusal mutation shown by hand to fail two checks.

### Cloud-neutral SCG and CPO scaffolds, pinned (MCE-10)

Reading the generators corrected the story's premise: `build_scg.render` and
`build_cpo.build_cpo` / `render_md` already take every fact from the offering
profile and the pinned dataset and name no cloud product; the committed
`package/scg` and `package/cpo` outputs contain zero AWS or Amazon mentions.
No production change. New pinning test
`validation/scripts/test_scaffold_platform_neutral.py` (in the validate suite)
renders both scaffolds for the template profile and for the non-AWS shape the
profile can express today (no `aws_partition`, no AWS regions, a neutral
`iac_technology`): neither names a cloud product or a registered third-party
vendor, the CPO is valid against the pinned CPO schema for both shapes with the
same members, and the AWS outputs are byte-identical to the committed
artifacts. The AWS-flavoured generated text lives in the explainer notes layer
that `build_sdr.build_extensions` copies into the SDR extension companion (and
that hard-reads `aws_partition`, `primary_region`, `dr_region`); that is a
separate story, not widened into this one.

### Evidence store requirements as properties (MCE-09; AUD-F73)

The evidence store the package expects is now stated as five PROPERTIES with
one attestation each (`versioned`, `write_once`, `separately_administered`,
`retention_days`, `access_logging`), no storage product or vendor named:
`sdr.EVIDENCE_STORE_PROPERTIES` defines them once, the offering profile
carries an `evidence_store` block (template values TBD; `implementation` is
optional free text), and `docs/automation.md` states them in their own
section, with the motivating identifiers verified in the pinned dataset,
before an "AWS implementation of the store" heading that now holds the S3,
`provision_store.py` and isolation-stack guidance. Building this exposed
`AUD-F73` (Medium): `evidence_store_profile: production-assurance` was the
provider's entire declaration of a tamper-evident store, one word with no
field behind it, so a provider on another platform had nothing to attest and
preflight could not tell a declaration from a hollow one.
`sdr.evidence_store_attestation_findings` reads the block and
`package-preflight` reports an absent or recorded-false attestation as a
readiness finding worded as what the package expects, never as a compliance
determination (the assessor assesses the store); the one blocker is a
production-assurance declaration over a store attesting neither versioning
nor write-once. Preflight does not verify the store against a live system.
The fictional Class C sample attests every property and gains one attack
probe (production-assurance with both tamper-evidence properties false blocks;
50 probes). Regression: `validation/scripts/test_evidence_store_properties.py`
(in the validate suite), red on the pre-change code; `MUT-F73` (contradiction
disabled) killed.

### Source registry binding for adapter checks (MCE-03; AUD-F72)

Adapters now bind exactly the `(service, check)` pairs they declare, per KSI
target, in the source registry the AUD-F62 provenance gate reads. Building
this exposed `AUD-F72` (High): the gate bound an adapter SERVICE-WIDE, so a
valid, signed entry claiming `crowdstrike:made_up_check` under `KSI-MLA-OSM`
classified bound, and the apply driver attached every entry of an adapter to
every one of its targets regardless of check. `EvidenceAdapter` gains
`checks`, `ksi_targets()`, `source_bindings()` and `declared_check()`;
`to_evidence` refuses a fact whose check is outside the declared vocabulary,
naming it. Falcon and Wiz declare their checks. The mapping schema requires
`checks` (as written in the export) and accepts per-check `check_bindings`
that narrow `ksi_targets`; both are verified against the pinned KSI profile
and the declared checks at build time. `validate_evidence.load_source_bindings`
records the declared pairs only (no `services` set any more) and registers
the mapping-driven sources the offering profile enables
(`mapping_adapter.register_from_profile`), so the gate, preflight and the
apply driver read one set of bindings; `classify_source_binding` loses its
service-wide branch (`MUT-F62` retargeted to the surviving branch and
re-killed). The apply driver attaches each entry only to the KSIs its pair
binds to and reports entries with no binding. Three Class C attack probes:
a declared pair under a non-target KSI blocks, an undeclared check under the
adapter's own target blocks, the declared pair under its target stays READY
(49 probes). The scaffold stub starts in the declared shape. Regression:
`validation/scripts/test_adapter_source_bindings.py` (in the validate suite);
`MUT-F72` (one Falcon check removed from the vocabulary) killed, and shown by
hand to fail the positive-control probe as well.

### Declarative export adapter, offline, mapping-driven (MCE-02; AUD-F70, AUD-F71)

A provider adds an evidence source by writing one JSON file against
`automation/collectors/adapter-mapping.schema.json`, not Python.
`automation/collectors/mapping_adapter.py` builds an `EvidenceAdapter` from
it: where in a customer-produced export (JSON lines, CSV, or a JSON document
with `records_path`) the check id, status, observation time, location, detail
and raw scope identifier live; how the source's status words normalize to
`PASS` / `FAIL` / `UNKNOWN`; which KSIs the facts support; which official SDR
`evidenceType` they become. Offline by construction (it reads the export text;
a test fails if a socket is opened). Facts meet the MCE-01 contract or the
batch is refused; a record with no observation time is refused, never dated.
Unmapped source states normalize to `UNKNOWN`, never `PASS`, with the raw
state kept in `detail` (`AUD-F70`, High, `MUT-F70` killed). An empty export
yields nothing and reports a collection outcome of `not-run` (`AUD-F71`,
`MUT-F71` killed). A mapping naming a KSI id absent from the pinned KSI
profile refuses to register, naming the id. Non-slug check ids become
deterministic, collision-free slugs (a digest of the original appended).
`apply_third_party_evidence.py` accepts `mapping_path` beside `export_path`
in `evidence_sources`, requires the key to equal the mapping's `name`, reads
`SDR_EVIDENCE_SCOPE_KEY` for raw scope identifiers, and attaches nothing for a
not-run collection. `evidence_wiring.register_service_evidence_type` lets a
mapping declare its service's evidenceType once; two adapters may not
disagree about one service. Fictional example mapping, JSON lines and CSV
exports and golden facts in `automation/collectors/fixtures/mapping/`.
Regression: `automation/collectors/test_mapping_adapter.py` (in the validate
suite), including the driver end to end in a temp copy.

### Neutral evidence fact contract (MCE-01; AUD-F68, AUD-F69)

`automation/collectors/fact-contract.schema.json` publishes the one shape every
evidence adapter yields, on any platform: required `service`, `check`,
`status`, `detail`, `region`, `observed_at` (a calendar-date prefix), optional
opaque `scope` and `run_id`, slug-safe key segments. `evidence_wiring` reads
the required and raw-scope field lists from the schema, so the document and
the enforcement cannot drift. `EvidenceAdapter.to_evidence` now checks every
fact of a batch against it before any is converted; a violation raises
`FactContractError` naming adapter, index and field, and nothing of that batch
reaches `fact_to_evidence` (`AUD-F68`: the contract had been a docstring, and
an adapter that forgot the timestamp produced undated evidence the freshness
gate could not see). The raw-scope refusal `AUD-F27` built for the AWS
`account` field now applies to every raw platform identifier the schema lists
(`account`, `tenant`, `subscription`, `compartment`, `project`,
`organization`): without an opaque scope or a scope key the fact is refused
naming the field; with a key the scope is derived per identifier kind and the
raw value appears nowhere in the evidence (`AUD-F69`, High). The AWS account
derivation is byte-identical to before, so no committed scope id changes.
`apply_third_party_evidence.py` fails closed on a refusal with the record
store untouched. The three existing adapters are proven byte-identical against
`automation/collectors/fixtures/adapter-golden-evidence.json`, captured from
the unmodified code. Regression: `automation/collectors/test_fact_contract.py`
(in the validate suite); `MUT-F68` and `MUT-F69` killed. The AWS collectors
(`collected_at` facts) are not routed through the adapter contract and are
unchanged.

### Third-party names: notice and CI guard (MCE-11, MCE-15)

`THIRD_PARTY_NOTICE.md` records every other organization's product name the
repository uses, its owner, and the one reason it appears: to identify an
export format an optional offline adapter reads. It states what the repository
does not do with those names (no evaluation, no compliance claims, no vendor
text or marks, no vendor clients, no real identifiers) and, like the LICENSE
and README, is subject to confirmation by AWS legal. The README links it.

`validation/scripts/test_third_party_names.py` joins the validate suite and
makes the mechanical parts of that policy a merge gate: a vendor watchlist name
that is not registered in the notice fails (G1); a sentence or code line that
names a registered third party and uses comparative, evaluative or endorsing
language fails, naming file, line and term (G2); an image file whose name
carries a vendor token fails (G3). Prose is split into sentences with table
rows as their own units, so unrelated rows are never fused. The guard runs a
21-shape self-test on every invocation before scanning, so a weakened lexicon
or parser fails the gate itself. Baseline on this commit: 0 findings across
357 tracked files. Existing CrowdStrike Falcon and Wiz mentions are registered;
the planned Google Cloud, Microsoft Azure, Oracle Cloud Infrastructure and
OpenSCAP adapter sources are pre-registered so their stories can proceed.

An external audit of main `80db0a6` (2026-10-12) rated the Class A path
NO-GO: the readiness contract imposed requirements FedRAMP does not impose on
the normal Class A alternative-framework path. Confirmed by execution and
closed, each with a regression test and a killed mutation (`AUD-F51` to
`AUD-F56`):

- **Class A is no longer over-blocked on a FedRAMP Recognized assessor or a
  Secure Configuration Guide (AUD-F51, High).** `required_gaps()` evaluated
  every required profile field regardless of class, so a Class A provider on
  the path FedRAMP allows (SOC 2 Type II within 12 months with the FRC-CLA-EAM
  materials, no FedRAMP independent assessment because `FRC-APP-FIA` is MAY at
  Class A, no SCG because `SCG-CSO-RSC` is not in the `FRC-CLA-MFR` set) was
  reported as missing `assessor`, `assessor_id` and `secure_config_guide_uri`
  and could not reach Submission ready. Preflight's FIA gate, its CPO scan and
  the package manifest already modelled Class A correctly; the contract did
  not, and the Class A end-to-end fixture filled all three fields, so it was
  never exercised. The contract now carries a class scope (`FIELD_CLASS_EXEMPT`,
  fail-closed for an unknown class; a selected `FRC-APP-FIA` brings the
  assessor requirement back exactly as preflight gates it), the published
  CDS-CSO-PUB items state that the rule does not apply instead of `TBD`, the
  generated CPO omits the two optional schema members where nothing applies
  and nothing was supplied (Class B artifacts byte-identical), and the wizard
  marks the three questions "not required at Class A, Enter to skip".
  `test_submission_readiness.py` now drives that Class A path to Submission
  ready and proves a selected `FRC-APP-FIA` blocks on the assessor again.
- **A CDS-CSO-PUB listing never makes a field unconditional by itself
  (AUD-F52).** CDS-CSO-PUB qualifies all 16 public items as "available and
  applicable" and the official CPO schema requires neither `assessor` nor
  `secureConfigurationGuidance`, yet nothing checked why a field was
  mandatory at every class. `CDS_CSO_PUB_BACKING` now names the applicable
  MUST requirement behind each identity-required CDS-CSO-PUB field, and
  `test_profile_contract_classes.py` verifies every backing and every
  exemption against the dataset, the class profiles and the schema's
  `required` lists (an optional schema member must be class-scoped).
- **The package-component gate matched class letters as substrings
  (AUD-F53, High).** The manifest scopes the Secure Configuration Guide
  component to "Class B and C"; the gate tested `"A" in "CLASS B AND C"`,
  which is true (the A in CLASS and AND), so the SCG scaffold blocked every
  Class A package. Found by the AUD-F51 end-to-end probe once the contract was
  fixed. `manifest_component_required()` matches the class letters as whole
  tokens.
- **Artifact requirements are classified per obligation (AUD-F54).** A
  rule's artifacts are separate items in the dataset, and
  `_classify_artifact` joined them into one string: one "if applicable"
  anywhere made the whole rule advisory, so a mandatory artifact beside a
  conditional one was never gated. The dataset has exactly one such rule
  today, CDS-CSO-SVC (MUST): its mandatory human-readable service-list URL was
  advisory at every class. `artifact_obligations()` classifies each item on
  its own (an item beginning "or " continues the previous one, the dataset's
  split "X; or an explanation why" form) and a rule is hard-gated as soon as
  any obligation demands an artifact; the gated set gains exactly CDS-CSO-SVC
  at every class, and the readiness suite proves a followed CDS-CSO-SVC with
  its artifact removed is blocked.
- **The class comparison table is rendered from the canonical data
  (AUD-F55).** `docs/certification-classes.md` disagreed with the files it
  describes in three places: a stale row still said Class B `SDR-CSX-KMT` is
  `MUST` beside the row saying `SHOULD`; "Indicators in scope" said "all 46"
  for Class B where the KSI profile has 41 baseline plus 5 optional; the
  Class D section said 157 register rules where the register holds 156.
  `validation/scripts/class_table.py` now renders the table from the class
  profiles, the Class D register, the KSI profile and the dataset's
  `SDR-CSX-KMT` forces (`--check` / `--write`), and
  `test_docs_class_table.py` in the CI suite fails on a hand edit of the
  table or of any count-bearing sentence.
- **A MAS-by-KSI coverage report for `FRC-CSX-MAS` (AUD-F56, new
  surface).** The package could show evidence for each KSI but not that no
  information resource inside the Minimum Assessment Scope had been
  forgotten. An optional provider-authored inventory
  (`profiles/common/mas-inventory.json`: the resources inside the MAS, each
  excluded one with a reason) is joined with the KSI set the package submits
  at each class into `artifacts/mas-ksi-coverage-class-<x>.json` and `.md`:
  one cell per resource and KSI, demonstrated only when the provider's
  reference resolves to a test method id or evidence location in that KSI's
  record, not applicable only with a reason, otherwise unresolved or a gap.
  Nothing is inferred and no status is set. All three classes render every
  build, the active class's files are fingerprinted in the release manifest,
  and preflight reports gaps as one advisory, never a blocker (the rule is
  SHOULD); with no inventory it says so.

That closes every item of the audit except the `sdr.py` decomposition it
rated P2 and asked not to combine with the policy fixes.

A fresh audit of main `3e41c24` (2026-10-13) confirmed the six closures above
and found one concrete evidence-integrity defect while reviewing the proposed
provenance-mutation family; driving its fix end to end found two more.
Confirmed by reading and by execution; closed, each with a regression test
proven red on the old code and a killed mutation (`AUD-F57` to `AUD-F60`):

- **Deleting an evidence entry's digest no longer bypasses a required signer
  (AUD-F57, High).** `classify_entry` returned the soft finding "no content
  hash yet" before `signer_required` was computed, so an actor who deleted
  `xEvidenceContentHash` together with `xEvidenceSignature` left an entry the
  required-signer gate never saw; the absent-signature (finding 8) and
  unresolvable-source (F01) downgrades beside it were hard, and the gate exits
  0 on findings. Reproduced end to end: the Class C sample with a pinned
  signer and its hand-written hashless evidence reached READY. The signing
  policy is now determined first; under a required signer a hashless entry is
  HARD, a hashless entry carrying a signature is HARD regardless of signer,
  and without a required signer it stays a finding (opt-in signing is
  unchanged). The sample now proves the downgrade blocks on a single entry.
- **Prefill proposes evidence through the canonical factory (AUD-F58).**
  `prefill_from_facts.py` hand-assembled evidence objects with no location,
  no source fact and no digest, so an accepted proposal entered the record
  store as evidence the integrity gate could never verify (and a hard failure
  under a required signer after AUD-F57). Every proposed entry, config and
  posture alike, is now derived by `evidence_wiring.fact_to_evidence`: bound
  displayed fields, sanitized source fact, recomputable digest, opaque scope
  for account-tagged facts, refusal (never a silent skip) when a fact cannot
  be scoped. `--location-base` (default `$SDR_EVIDENCE_LOCATION_BASE`) gives
  concrete pointers; without it the pointer is the explicit `sdr://placeholder/`
  pseudo-URI preflight refuses, and because the pointer is a bound field the
  entry is re-derived rather than edited.
- **Under production-assurance, evidence counts toward linkage only when
  verified (AUD-F59).** The SDR linkage gate tests presence (a non-empty
  evidence array) and the integrity gate exits 0 on findings, so an
  unverifiable entry satisfied Class C/D linkage while proving nothing.
  Preflight, under `evidence_store_profile` production-assurance only, runs
  every entry behind each populated applicable record (KSI evidence and FRR
  rule artifacts) through the live classifier with the pinned signer and
  blocks when any outcome is not `verified`, grouped by outcome. The
  development profile is unchanged: a finding stays a finding, collection
  failure is not control failure, and template records never count. The
  Class C sample's production-assurance READY probe now carries bound, hashed
  and signed evidence, proving the profile remains satisfiable.
- **A signed evidence entry no longer publishes the signer's account id, and
  can pass the package gate (AUD-F60, High).** Found by driving that READY
  probe end to end: `sign_hash` recorded the KMS key ARN verbatim as the block
  `keyId`, the ARN is the documented pin form, and a signed entry is rendered
  into the SDR and the record store, both scanned by `no_sensitive_patterns`.
  Every correctly signed production package therefore failed its own
  validation gate, with the audit account id in the package. The block now
  records `key_reference(key id)` (a key ARN reduces to its key id, an alias
  ARN to `alias/<name>`), KMS is still called with the full key id, and the
  verifier compares the block and the pinned `key_arn` in reference form, so
  existing ARN pins keep working and a different key is still refused.
- Two Class C attack probes had quietly stopped testing anything: they
  hollowed the `cpo_required_information["CDS-CSO-PUB"]` override, which the
  AUD-F39 one-place-per-fact derivation ignores in favour of the profile
  fields (so the package was correctly READY, and both probes reported a
  false "reached READY despite tamper"). They now hollow the derived source
  fields (verified to block with three blockers each), and a new probe proves
  the ignored override keeps the package READY. The attack suite is still a
  manual run (`--attack`, 43 probes), which is why this went unnoticed.

The attack suite is a manual run no longer (`AUD-F61`, Medium): the Class C
assessor-attack harness is now the `attack` section of the one release gate
(`audit/release_gate.py`, in `SECTION_ORDER`), with a tree-clean step after it
because the harness restores every file it overwrites. CI runs it as its own
parallel `attack-gate` job and the required `release-gate` aggregate now needs
all four jobs; the AWS `RELEASE_MODE` build and `sdr.py release` run `audit
attack security`. `test_release_gate.py` asserts the section, the step's
`--attack` argv, the job, the aggregate's dependency and both executors
(68/68), and `MUT-F61` (the harness dropped from the gate) is killed. About 20
minutes per run, in parallel with `validate`.

Evidence provenance is now bound semantically, not only cryptographically
(`AUD-F62` to `AUD-F64`). The digest and signature prove an entry was not
edited after it was recorded; nothing proved it belongs where it sits:

- **An entry's source must be a registered source for its KSI (AUD-F62,
  High).** No gate read the collector registry's per-KSI binding
  (`metric_service_keys`, Config rule checks) that prefill and the metric
  engine already honour, so an entry derived from a valid observation of a
  different indicator, with a recomputed digest and a real signature, was
  `verified` and counted toward Class C linkage under production-assurance.
  The 11 artifact-existence KSIs had no registry source at all (their deployed
  rule names live only in `automation/config-rules/rules-manifest.json`), and
  the Class C sample attached every KSI's signed evidence to a fictional
  Security Hub check nothing maps to the indicator, and reached READY.
  `validate_evidence.load_source_bindings` joins the registry, the rules
  manifest and the registered third-party adapters' `ksi_targets()` into one
  per-KSI map; `classify_source_binding` is pure (`bound` / `unbound` /
  `no-claim` for entries without a source fact, which stay a human's review).
  The integrity gate reports an unbound entry as a readiness finding and
  `package-preflight` blocks on it behind a populated applicable record under
  production-assurance (the AUD-F59 pattern; development unchanged). Every one
  of the 46 KSIs has at least one registered source (asserted), so the gate is
  satisfiable; the sample now derives each KSI's evidence from
  `first_bound_source`.
- **An entry's pointer must describe its own source fact (AUD-F63, Medium).**
  The factory builds `evidenceLocation` from the fields it stamps into
  `xSourceFact`, but nothing re-checked the relation, so a pointer re-targeted
  at another observation (region, scope, run or check), recomputed and
  re-signed, verified. `classify_pointer_binding` rebuilds the expected slug
  and requires the pointer to end in it; KSI evidence and FRR rule artifacts
  alike; finding at the gate, blocker at preflight under production-assurance.
- **Freshness proven load-bearing against an internally valid entry (AUD-F64,
  Medium).** The classifier had tests but no mutation and no fixture with a
  stale observation carrying a recomputed, re-signed digest, the one shape only
  the freshness policy can stop. No production change; the regression binds
  the dimensions and `MUT-F64` (never `expired`) is killed.

The regression family `test_provenance_mutations.py` (46 checks) tampers one
dimension at a time, recomputes the digest and re-signs with the pinned key,
and asserts the cryptographic gate stays silent while the one semantic gate
catches it (the HASH family covers every tripwire shape: deleted, corrupted,
kept-after-edit, stale binding, re-signed by an unpinned key). `MUT-F62` to
`MUT-F64` killed; `MUT-F01`, `F26`, `F57`, `F59` re-killed. The attack harness
gains three production-assurance probes (wrong-KSI source, swapped pointer,
400-day-old observation, each recomputed and re-signed) and its READY probe
stays READY with bound sources.

A certification class has one interpretation (`AUD-F65`, Medium).
`validation/scripts/class_support.py` is the single state: `SUPPORTED` (a, b,
c), `FUTURE` (d), `INVALID` (anything else, never read as pending D). Before,
thirteen entry points carried their own `if cls == "d"` guard with thirteen
messages, two carried `not in ("a", "b", "c")`, and the generic resolvers
underneath did not know Class D existed: `submitted_ksi_ids` special-cased only
Class B and returned the full KSI set for `d` and for any typo,
`submitted_rule_ids` special-cased only Class A, and the MAS coverage resolver
sent everything that was not a or b to the all-KSIs branch; an unknown value
such as `e` fell through every guard into generic processing (a missing
class-e profile and a traceback, or a document labelled Class E). Every entry
point (the fourteen builders and validators, `sdrscan`, `package-preflight`)
now prints the one message (`CLASS_D_NOT_SUPPORTED_YET` with the readiness
register path, or `INVALID_CERTIFICATION_CLASS`) and returns 1 before any
write; the three resolvers raise `UnsupportedCertificationClass` (a
`ValueError`) instead of returning a plausible set. The Class D readiness
register keeps its own explicit path (`build_profiles.py`). The dataset
carrying some Class D values is not support for Class D.
`test_class_support.py` (53 checks) drives every entry point in process with
a Class D and an invalid profile and asserts exit 1, the one message and no
exception, and fails if a scattered guard reappears; `MUT-F65` (Class D added
to the supported set) is killed. No generated artifact changes.

The audit's one remaining item is open by decision, not oversight:
machine-readable per-gate results with a reverse rule-to-test map. The
`sdr.py` decomposition is withdrawn: the file stays as it is.

That item is closed too (`AUD-F66`, `AUD-F67`, both Medium), which leaves the
2026-10-13 audit with nothing open:

- **The release gate leaves a machine-readable record (AUD-F66).** `run_step`
  returned an integer and `run()` printed a line, so which gate ran for a
  release, with what argv and how it ended could only be read from job logs.
  `run_step` now returns a record (`gate_id` `<section>.<name>`, argv, exit
  code, status, error when a tool cannot start) and `run()` writes
  `validation/reports/gate-results.json`: one entry per executed step, the
  steps a failure stopped, the overall verdict, class and dataset version, and
  nothing volatile, so identical runs write identical bytes. In GitHub Actions
  a separate `gate-results.run.json` envelope records commit, run id, job and
  time; CI uploads both per section. Gitignored run evidence, never a committed
  deliverable; the exit code is still the verdict. `MUT-F66` (results never
  written) killed; `test_release_gate.py` 88/88.
- **A reverse rule-to-gate-to-test-to-mutation map (AUD-F67).** For a rule or
  indicator: which automated check enforces anything about it, which regression
  test protects that check, which killed mutation proves the test detects the
  defect. `build_rule_test_map.py` (a build step, so regenerate-and-diff
  checked) joins the scanner catalog's `fedramp_basis`, the defect ledger's
  requirement / regression_test / mutation fields, the mutation runner and the
  gate registries into `traceability/rule-test-map.json`, deterministically.
  Every identifier is resolved against the rule catalog, the KSI catalog and
  the dataset's FRD definitions; what does not resolve is reported under
  `unresolved_references` (the retired `FRC-CSX-MOT` citations of older
  entries stay historical), never dropped or invented. A per-class coverage
  block lists the applicable identifiers with an automated disposition and the
  rest as `human_review_only`: Class A 11 of 48, Class B 20 of 198, Class C 20
  of 203. That is a coverage figure, not a defect list, and an entry never
  means a provider complies. Building the join exposed that this round's
  `AUD-F61` to `AUD-F63` had cited `SDR-CSX-VER` and `SDR-CSX-VAL`, identifiers
  the pinned dataset does not carry (the verification and validation language
  lives in `SDR-CSX-KSI` and `FRC-CSX-VVK`); corrected. `MUT-F67` (unresolved
  identifiers dropped silently) killed; `test_rule_test_map.py` checks every
  reference and recomputes the coverage.

The documented consultant flow, run end to end on a fictional Class B offering
(`init` with every answer scripted, the three importers, prefill, the drafter,
`review --list`, `--walk`, `--accept-all prefill`, `build`, `preflight`),
found six defects in the review and profile path that no committed sample
exercised. All six are closed with a regression test and a killed mutation
(`AUD-F45` to `AUD-F50`):

- **A sidecar proposes only what its producer authors, and a decision stands
  (AUD-F46, High).** Both sidecars are full snapshots of the record store.
  After one narrative was accepted, the prefill snapshot's `TBD` for that
  field read as a prefill proposal to put it back, prefill outranks the
  drafter, and `review --accept-all prefill` silently reverted the accepted
  narrative to `TBD` ("Applied 28 field(s)"). Separately, a decided prose
  proposal never equals its labelled sidecar value, so `--list` never shrank
  for prose and `--walk` re-asked every decided field. `review_proposals.py`
  now applies an authorship guard (prefill: structured tests/evidence only;
  the drafter: `DRAFT`-labelled implementation/validation prose only;
  anything else in a sidecar is the snapshot) and partitions out proposals
  whose hash the field-review log already records a decision for; `--list`
  prints the decided count and `review --all` includes them. A changed
  proposal is pending again.
- **`init --set` accepts the keys its own gap report prints and refuses the
  rest (AUD-F45).** `cpo_metadata.cpo_version` and the other three
  CPO-CSO-MTD keys were printed as required but silently ignored by `--set`
  (the block is flat; only the bare key was consumed), and any unknown key
  was ignored the same way. Both forms now work; an unknown key, a key for
  another class, or a malformed item is refused by name and nothing is
  written.
- **CPO-CSO-MTD is answered once (AUD-F50).** With the four metadata
  answers written, preflight still blocked "CPO required information
  unresolved (CPO-CSO-OVR): CPO-CSO-MTD" because that list item read only a
  separate `cpo_required_information` pointer; the same facts had to be
  typed again by hand in JSON. The item now derives from the four profile
  fields the wizard asks, as CDS-CSO-PUB already did; a real pointer still
  wins.
- **Structured tests and evidence cannot be edited into prose (AUD-F47).**
  `[e]dit` on a prefill item wrapped the reviewer's sentence into the list
  of schema objects (schema-invalid; zero automated methods to FRC-CSX-VVK).
  The walk offers accept/reject/skip/quit on a structured item and
  `apply_decisions` refuses an edit there by name.
- **Prefilled text carries no markdown (AUD-F48).** The method and evidence
  templates wrapped the rule name in backticks; once accepted, the
  human-readable SDR failed the gate's `no_markdown_in_human_readable` check
  for every class. Plain text now; the regression runs the gate's own
  patterns over prefilled output and the drafter's.
- **The drafter sees the indicator's own Config-rule facts (AUD-F49).** A
  KSI proposal said "no automated facts collected for this indicator yet"
  one review item after prefill had proposed that indicator's Config-rule
  evaluation as its test. The drafter now reads Config-rule facts the way
  prefill does and names them first in the observed-posture line.

The zero-typing track completes its importer set:

- **An existing Rev5 SSP and a landing-zone configuration become KSI
  proposals.** New `automation/importers/import_oscal_ssp.py` reads an OSCAL
  System Security Plan (NIST OSCAL v1.1.x field names) and joins its
  `by-component` implementation descriptions to the KSIs through the
  dataset's own control lists (`KSI.<family>.indicators.<id>.controls`,
  OSCAL ids), so each KSI's proposal quotes the provider's assessed Rev5
  narrative for exactly the controls FedRAMP ties to that indicator, tagged
  with control, statement, component and the SSP's declared status as text.
  The SSP's status is never written as a 20x `implementation_status`; party
  names, system ids and inventory never cross; a control no KSI lists is
  reported, not mapped; per-KSI coverage names the dataset controls the SSP
  does not implement. New `automation/importers/import_landing_zone.py` reads
  Landing Zone Accelerator `global-config.yaml` and `security-config.yaml`
  (field names verified against the LZA Universal Configuration) and emits
  observations that all begin "Landing zone configuration declares", routed
  to KSIs only through the registry's `metric_service_keys` allowlist and its
  Config-rule checks (rule identifiers through the pinned catalog
  identifiers), plus `VDR-CSO-ADT` and `VDR-CSO-DFR`; its facts file carries
  `DECLARED_ONLY` with empty `facts` and `posture_facts`, so declared intent
  contributes to no metric or evidence. `draft_narratives.py` now quotes
  imported KSI observations (bounded: 6 items, 2400 characters) into the KSI
  proposals, drafts KSIs on imported observations alone, and keeps a
  provider-written 4-argument drafter working. Fixed alongside: every KSI
  proposal's "Intended measure" was empty because the drafter read guidance
  from the collector registry entry, which carries none; it now reads the
  record's `fill_guidance`. PyYAML 6.0.3 is added to `requirements.txt`,
  `setup.py` and the hash-locked `requirements.lock` (every PyPI artifact
  digest; installed in a clean venv with `--require-hashes` and audited).
  22 offline tests across the two importers plus 2 drafter regressions, all
  in the CI suite. Exercised end to end on a fictional eleven-control SSP and
  a fictional landing zone: 14 and 17 KSIs received observations, 46 KSI
  proposals pending in `sdr.py review --list`, the appender saw zero facts
  from either file.

The zero-typing track gains its first importer:

- **AWS Config and Security Hub exports become collector facts without
  credentials.** New `automation/importers/import_findings.py` reads the JSON
  a customer produces with four read-only AWS CLI commands
  (`describe-compliance-by-config-rule`, `describe-config-rules`,
  `describe-config-rule-evaluation-status`, `securityhub get-findings`),
  detected by top-level key, and writes the same facts-store shape the live
  collector writes, so prefill, the metric appender, the drafter and the
  review step consume it through their existing paths. Mapping is data only:
  exact catalog id, Security Hub's service-linked `securityhub-<id>-<suffix>`
  convention, the rule's `Source.SourceIdentifier` through catalog
  identifiers now pinned in `known-config-managed-rules.json` (read from the
  AWS Config Developer Guide; `restricted-ssh` is `INCOMING_SSH_DISABLED`,
  `restricted-common-ports` is `RESTRICTED_INCOMING_TRAFFIC`,
  `cloudtrail-enabled` is `CLOUD_TRAIL_ENABLED`,
  `multi-region-cloudtrail-enabled` is `MULTI_REGION_CLOUD_TRAIL_ENABLED`),
  then the provider's own `config-rule-name-map.json`. An unmatched name is
  never guessed; it is printed as a review queue and stored in the facts
  file's meta. Several instances of one rule aggregate worst-wins. The
  import derives dated, count-only observations for `VDR-CSO-DET`,
  `VDR-CSO-RES`, `VDR-CSO-ADT` and `VDR-TFR-MVX` (ids checked against the
  pinned dataset across every applicability branch), and
  `draft_narratives.py` quotes them into those rules' labelled proposals so
  the proposal names the provider's own findings rather than only the
  official how-to text. No finding titles, ids, resource ids, ARNs or account
  ids are kept. Refusals: no observation time in the export needs
  `--observed-at` (exit 2); an export cut short yields an unscorable
  `OBSERVED_PARTIAL` fact; one source per region (the import is refused while
  a live collection for the region exists, and the live collector warns when
  an import does), since the appender sums posture facts per route across
  files; exit 4 when nothing was evaluated, as the collector does. 27 offline
  tests in `automation/importers/test_import_findings.py`, in the CI suite;
  the vocabulary gate asserts the pinned identifiers stay aligned with the id
  list. Exercised end to end on a fictional nine-rule, nine-finding export:
  8 rules mapped (a Control Tower instance resolved through its identifier),
  one custom Lambda rule queued, 18 prefill and 8 observation-bearing rule
  proposals pending in `sdr.py review --list`.

The drift workflow's second pin follows the first (`AUD-F44`, Medium, with a killed mutation):

- **A dataset adoption advances the markdown-changelog baseline (AUD-F44).** The
  daily check compares FedRAMP's `2026-markdown` changelog against a committed
  hash. The `2026.10.05.01` and `2026.10.08.01` adoptions advanced every
  dataset pin but not that hash, so the scheduled run after each one failed
  and re-reported, as new drift, the entry the adoption's reviewer had already
  read (run 38051982680 on `95649fb` opened issue #211 for the entry PR #207
  adopted). New `validation/scripts/markdown_changelog.py` extracts FedRAMP's
  changelog entry for a dataset version and advances the baseline; the
  adoption step fetches the changelog fail-closed, puts that entry in the
  review body above the machine diff, and writes the baseline in the adoption
  commit, only when the entry exists, so an entry FedRAMP has not published
  yet still surfaces through the daily check. For a markdown-only change the
  drift issue names the one-command human path. The committed baseline was
  advanced to the 2026-10-08 changelog after reading it, and #211 closed with
  the trail. Three workflow tests beside the `AUD-F43` ones (red on `95649fb`'s
  workflow, green after), seven offline helper tests, `MUT-F44` killed.

## 1.6.0, 2026-10-10

Pinned dataset: `2026.10.08.01` (adopted 2026-10-10 from `2026.10.05.01`; `2026.10.05.01` adopted 2026-10-08 from `2026.09.13.02`)

From typing to deciding, inputs traced to FedRAMP, and the first two dataset
adoptions carried by the drift workflow. Since `1.5.0`: machine proposals are
unanswered until a named human accepts them, and `sdr.py review --walk` replaces
hand-editing JSON (`AUD-F38`); the offering profile is a contract in which every
required field names its Certification Package Overview schema property or CR26
rule, `sdr.py init` asks every one of them, and the template ships no prose this
project wrote (`AUD-F39`); CR26 `2026.10.05.01` and then `2026.10.08.01` were
detected by the daily drift check, regenerated and validated by the workflow,
and adopted by review, the second removing `FRC-CSX-MOT` and making
`SDR-CSX-KMT` a SHOULD at Class B, so the persistent-validation gate is
re-grounded on the rule that now carries it, with no minimum history duration
because the dataset has none (`AUD-F42`); and the adoption path itself was
repaired where those two releases exposed it: curated pins that did not advance
(`AUD-F40`), a change summary that under-counted (`AUD-F41`), and a PR hand-off
that swallowed GitHub's refusal (`AUD-F43`). Six findings closed, each with a
killed mutation; the independent oracle reconciles clean at 41 / 157 / 157.
Release tag: `v1.6.0-cr26-2026.10.08.01`. Entries are newest first within each
sub-lead.

The drift workflow's review hand-off is fail-visible (`AUD-F43`, High, with a killed mutation):

- **A refused PR creation is reported, not swallowed (AUD-F43).** The
  2026-10-09 scheduled run detected CR26 `2026.10.08.01`, regenerated and
  validated the package and pushed `drift/dataset-2026.10.08.01`, then GitHub
  refused `gh pr create` ("GitHub Actions is not permitted to create or approve
  pull requests") and the step printed "PR may already exist for this dataset
  version." and exited 0. The branch push had the same `|| exit 0` shape. Both
  hand-offs now check their one benign cause instead of assuming it (the branch
  already on the remote via `git ls-remote`; an open PR for the branch via
  `gh pr list --head`); any other failure fails the step. When the PR cannot be
  opened, the branch, commit, compare link and the full review body are posted
  on the open drift issue (or filed as a new issue), an `::error::` annotation
  names the repository setting that usually causes the refusal, and the step
  exits 1. Enabling "Allow GitHub Actions to create and approve pull requests"
  in the repository settings makes the PR open directly; that setting is the
  owner's decision and is not changed by this repository.


CR26 dataset `2026.10.08.01` adopted:

- **Detected and regenerated by the drift workflow, adopted by hand.** The
  2026-10-09 scheduled run detected the release, opened issue #206, swapped the
  dataset and rules schema, advanced the lock and every curated pin, rebuilt
  all three classes (21 steps, 0 failures), validated (0 hard failures) and
  pushed `drift/dataset-2026.10.08.01` at `c95c7cb`. It could not open the
  review PR: the repository does not allow GitHub Actions to create pull
  requests, and the workflow treated that refusal as "PR may already exist"
  (fixed separately as AUD-F43). This PR is that branch plus the human half
  below. Upstream change by recursive diff: 1 rule removed, 0 added, 3 changed
  (one with a force change), KSI set unchanged (46 in 10 families); 245 entries,
  233 in 20x scope; Class B and C resolve 157 rules (158 before), Class A 41.
  The official changelog calls the release "typos and convenience only"; the
  removal and the force change below are the two provider-relevant items.
- **FRC-CSX-MOT ("Metrics Over Time for Key Security Indicators") is removed**
  as duplicative of SDR-CSX-KMT. With it goes the only minimum history
  duration the dataset had ("at least the past 6 months" at Class C, 18 at
  Class D). Its initial-certification note moved verbatim to SDR-CSX-KMT.
- **SDR-CSX-KMT is SHOULD at Class B** (MUST before: "Changed MUST to SHOULD
  for Class B, added note, clarified persistent validation status should be
  included"), stays MUST at Class C, where the third item now reads "All daily
  metric data (including status of persistent validation) up to the past year
  (where available)". CMU-CSO-UVM and MKT-IAS-LRQ changed only their `updated`
  history.
- **The persistent-validation gate is re-grounded on SDR-CSX-KMT** (preflight,
  `append_metrics.py`, scanner, validator, Word documents, notes, docs). What
  changed in behaviour, by class:
  - Class C and D: no 6- or 18-month floor. Each KSI's coverage of the
    up-to-one-year reference period is measured and reported; a shorter span
    is the provider's "where available" statement for the assessor, not a
    verdict. The recorded initial-certification commitment
    (`metric_history_exception`, name kept) is required when the offering's
    metrics have been available for less than the reference period, per the
    rule's note, with a current datapoint per KSI; its eligibility window is
    now the reference period (was 6 months). A KSI wholly absent from the
    history and a series whose status was not known across the evaluated
    window (continuity, the AUD-F21 project tolerance, now citing FRD-PER)
    stay blockers. Net effect: an offering with between six and twelve months
    of metrics now records the commitment where before it did not; one with
    less than six months is treated as before.
  - Class B: missing 30-day or up-to-one-year summaries and a missing
    per-metric breakdown are one advisory for the class, not per-KSI blockers;
    a summary that contradicts the durable history stays a blocker at every
    class. The scanner reports the two summary checks as MANUAL at B.
  - `append_metrics.kmt_window` (alias `mot_window`) records
    `reference_months`, `covered_days` and `covers_reference_period` per KSI
    instead of a class minimum and `meets_window`.
  - The independent oracle's anchors are 41 / 157 / 157; `test_requirements_oracle`
    RULE 7 pins 157. README counts, the certification-classes table, the
    scanner README and the pipeline comments are force-accurate.
- **Orphaned records are reported (AUD-F42, Medium, with a killed mutation).**
  The bot's regenerate left the FRC-CSX-MOT record in the store with its
  guidance hollowed to "See rule catalog." and nothing said so: the scaffold
  only ever adds records. `build_sdr.orphan_record_ids` now names every store
  record whose rule or KSI the dataset no longer defines; the build prints them
  and `package-preflight` reports them as an advisory (never pruned: that is the
  reviewer's call). The orphan is removed from the template store and the Acme
  sample store here. `test_orphan_records.py`; `MUT-F42` killed.
- The Class C sample's fictional history spans 400 days (past the reference
  period) and the readiness fixture 13 months, so neither needs the commitment.
  At adoption the release manifest's `release_tag` read
  `v1.5.0-cr26-2026.10.08.01`; this release bumps it to
  `v1.6.0-cr26-2026.10.08.01`.
- The committed Acme sample outputs are regenerated for `2026.10.08.01` by the
  sample builder as documented (gate PASS, live tree restored): the sample SDR
  no longer carries the removed rule's section and the 24 FRC-family
  `how_to_comply` strings cite `SDR-CSX-KMT` instead of `FRC-CSX-MOT`.

Pinned dataset before this adoption: `2026.10.05.01` (adopted 2026-10-08 from `2026.09.13.02`)

CR26 dataset `2026.10.05.01` adopted:

- **Adopted by the drift workflow's own regenerate-and-review path** (first
  adoption through it; the path is the AUD-F40 fix below). Upstream change
  between `2026.09.13.02` and `2026.10.05.01`: 7 rules changed, 0 added,
  0 removed, 0 force changes; the KSI set is unchanged (46 KSIs, 10 families;
  the service map's ids, names, families and canonical control lists
  re-verified). The workflow's own summary said 4 rules; it compared a fixed
  list of fields and missed the rest (AUD-F41, fixed separately). Lock, every
  curated pin, all three classes' SDR (JSON, text, Word), the CPO, the OCR and
  event examples, the profiles, the catalogs and the reports regenerated;
  `sources.lock.json` `verified_current_on` stamped 2026-10-08 by the updater.
  No status changed and no assessment written.
- **VER-EVA-EPA gained a PAIN rating.** `following_information_bullets` now
  includes, verbatim: "**N0**: Exploitation is extremely unlikely to have any
  adverse effects on agencies that use the cloud service offering."; the
  statement now reads "estimate the likely potential agency impact"; "Likely"
  joined the rule's `terms`. The upstream comment: "added PAIN0 to clarify
  that likely potential agency impact can be entirely mitigated/remediated."
  A Vulnerability Detail Report cannot record N0 yet: the pinned
  common-definitions schema (`$schemaVersion` 0.4.0) defines `nRating` as
  `enum [1, 2, 3, 4, 5]` and the document schemas are unchanged upstream, so
  N0 is rule text today and a schema adoption when FedRAMP ships one (the
  daily schema hash check surfaces it).
- **FRC-CSO-JSN now names public-JSON delivery expectations.** The statement
  gained "public JSON data MUST be supplied in a manner compatible with modern
  web frameworks, including:" with two `following_information` items (CORS
  should allow other domains to read the public JSON; Content-Type
  application/json and X-Content-Type-Options nosniff should be set), and two
  new `notes`, one of which reads: "The Schema Validator available at
  fedramp.gov will not work properly if Cross-Origin Resource Sharing is not
  properly configured." `automation/pipeline/check_json_download_headers.py`
  now reports `Access-Control-Allow-Origin` alongside the two headers it
  already checked, labels each header with its source (the rule, or the
  2026-09-15 Help Center guidance for `Content-Disposition: attachment`), and
  its documentation no longer says these headers are absent from the dataset.
  It stays advisory and reports presence only; the FRC-CSO-JSN decision
  belongs to the provider's record and the assessor (`docs/ci-cd.md`).
- **CDS-CSO-PUB "Link to Product Logo"** gained "(must be a valid image link,
  properly named, that will display in a browser without processing -
  transparent PNG preferred)", and a new note: the JSON for this rule "will be
  consumed by FedRAMP and agency GRC tools using automation with web-based
  tools", with FedRAMP recommending that application engineers be involved.
  The profile contract already derives this item from `offering_logo_uri` by
  the text before the parenthetical, so the derivation is unchanged; the
  wizard's question and the CPO schema's image extension pattern already ask
  for an image link.
- **CMU-CSO-UVM** gained a note: algorithms added by a cryptographic module's
  update stream that were never validated are outside the scope of
  validated-module update usage. Note only; no package field changes.
- **MKT-CAS-LRQ and MKT-IAS-LRQ** (marketplace listing requests for advisors
  and assessors; not provider rules) changed their notification form names,
  and the assessor form moved to Help Center ticket form `54220455254427`.
- **FRC-CSF-RDY** wording only ("following dates"); regenerated into every
  rule record and catalog.
- README badge, pinned-version line and derived counts (246 entries, 234 in
  20x scope, 46 KSIs: re-counted from the new dataset), the illustrative
  outputs in `docs/getting-started.md` and `automation/sdrscan/README.md`,
  and the service map's provenance note (now describes the standing
  verification instead of naming one past version) updated by hand.
- The release manifest's `release_tag` now reads `v1.5.0-cr26-2026.10.05.01`:
  same framework version, new dataset suffix, a tag distinct from the published
  `v1.5.0-cr26-2026.09.13.02` (`docs/versioning.md`: two versions, always
  both). Whether to cut it is a maintainer decision.

The adoption summary reports every changed rule field (`AUD-F41`, High, with a killed mutation):

- **`dataset_diff.py` compares the whole rule, not a chosen list of fields
  (AUD-F41).** For `2026.09.13.02` to `2026.10.05.01` it reported "4 rules
  changed" and the impact report listed 3 items for review; a recursive diff
  shows 7 rules changed, including the new PAIN **N0** rating in
  VER-EVA-EPA's `following_information_bullets`, new `notes` on CDS-CSO-PUB,
  FRC-CSO-JSN and CMU-CSO-UVM, changed notification forms on MKT-CAS-LRQ and
  MKT-IAS-LRQ, and `terms` additions. The tool's own comment records the same
  failure for `2026.09.13.02` (timeframe ranges), fixed then by adding names
  to the list. Every key of the rule object except the `updated` history is
  now compared; a key the tool has no name for is reported under its own name
  and counted in the summary line; list changes show the items added and
  removed; the rule's `updated` entry is carried as the upstream comment.

The adoption path works end to end (`AUD-F40`, High, with a killed mutation):

- **Curated `dataset_version` pins advance with the dataset (AUD-F40).** The
  2026-10-07 drift run detected CR26 `2026.10.05.01`, swapped the dataset,
  refreshed the lock and rebuilt, then stopped at the build's own consistency
  check: `assurance graph dataset 2026.10.05.01 != offering 2026.09.13.02`.
  The offering profile's pin (and the sample profile's, the pending-KSI
  classification's, the Config rules manifest's and the AWS service-KSI map's)
  is a curated input nothing regenerates, so the adoption PR was never opened
  and issue #198 was the only trace. `update_sources_lock.py`, which the drift
  workflow and the documented manual adoption already run, now advances every
  curated pin with a one-line edit proven to change nothing else. The service
  map's pin is a verification claim, so it advances only after the script has
  re-verified the map's KSI ids, names, families and canonical control lists
  against the new dataset; otherwise it is held and reported. `test_dataset_version_consistency.py`
  takes its file list from the updater (one definition) and re-runs that
  verification instead of trusting the pin.
- **The adoption commit includes the regenerated Word documents.** The drift
  workflow staged everything except `*.docx`; since AUD-F35 the documents are
  reproducible and CI refuses a tree whose generated files differ from the
  committed ones, so every adoption PR would have failed that gate.
- Verified against upstream `2026.10.05.01` in a throwaway clone: lock and five
  pins advanced, `sdr.py build` 21 steps 0 failures, `sdr.py validate
  --no-tests` 0 hard failures. Upstream change in that release: 4 rules
  changed, 0 added, 0 removed, 0 force changes (CDS-CSO-PUB logo wording,
  FRC-CSO-JSN statement plus two CORS/header expectations, FRC-CSF-RDY and
  VER-EVA-EPA statements); the KSI set is unchanged.

Earlier in this cycle:

Pinned dataset: `2026.09.13.02` (unchanged)

From typing to deciding (`AUD-F38`, High, with a killed mutation):

- **A labelled proposal is unanswered until a named human accepts it
  (AUD-F38).** Text beginning `DRAFT (`, `Example (` or `Example:` counted as
  a populated, answered narrative in `package-preflight`, `validate_sdr.py`
  and the scanner; at `35aa70c` the template's Example implementation of
  AFC-CSO-INB satisfied the SDR-CSO-FRR "reason not followed" element, and
  three rules plus three KSIs read as populated. One shared definition
  (`validation/scripts/unreviewed_text.py`) now feeds every predicate, so a
  package whose narratives are all machine drafts reads as exactly as unfilled
  as one full of TBDs. Template blocker counts rise accordingly; that is the
  honest number.
- **`sdr.py review --walk` replaces hand-editing JSON.** It lists every pending
  proposal (the collector prefill sidecar, the AI-draft sidecar, and the
  labelled examples shipped in the template) with its current value, the
  proposal, its provenance and exactly what would be written, and takes one key
  per field: accept (label stripped), edit (the reviewer's text), reject or
  skip. `--accept-all prefill` bulk-accepts deterministic collector facts
  (structured tests and evidence), never prose; `--decisions FILE` applies a
  prepared set; `--list` is read-only. It refuses to run without `--reviewer`
  and `--role`, refuses a pipeline identity, and never writes
  `implementation_status` or `assessment`. The register report
  (`sdr.py review` with no flags) is unchanged.
- **Every decision is recorded and bound.** `sdr/reviews/field-review-log.json`
  (new, shipped empty) records reviewer, role, timestamp, source, provenance
  (collector run id, facts digest, drafter) and the SHA-256 of the proposal and
  of the written value. `validate_reviews.py` checks the log in the gate and
  FAILS when the latest accepted or edited field was changed afterwards without
  a new decision.
- **The drafter proposes every rule narrative.** `draft_narratives.py --scope
  rules` drafts the 168 FRR process rules with no collected facts needed: a
  labelled `Example (` value a fork may still carry for that field when
  present (kept verbatim, re-labelled as a proposal; the shipped template
  carries none, see below), else the
  CR26-derived `fill_guidance` with the offering profile's real values named
  (organization, offering, security and incident contacts, trust center;
  template placeholders are never treated as facts). Same forbidden-field
  boundary as KSIs. Default `--scope all` drafts KSIs (facts required) and
  rules; KSIs are skipped with a notice when no facts exist.

Only what FedRAMP requires, asked by the script:

- **The template ships no example prose.** The 48 `Example (reference
  architecture, replace with your real implementation): ...` values the
  record store carried since `688c27c` (three rules, three KSIs) and the
  profile's "Example PaaS Foundation" identity were text this project wrote,
  with no FedRAMP source. They are gone: every narrative field is a `TBD`
  marker plus the official `fill_guidance`, and `--scope rules` drafts from
  that guidance alone. Nothing the framework authored can be mistaken for a
  provider's fact, and the review walk has nothing to accept that a human
  did not first say.
- **The offering profile is a contract traced to FedRAMP.**
  `validation/scripts/profile_contract.py` is the one definition of what the
  profile must contain: 22 fields required at every class and six class-
  conditional blocks, each naming its source as a Certification Package
  Overview schema property (`cpo:serviceIdentification.serviceName`) or a
  CR26 rule id (`CDS-CSO-PUB`, `FRC-APP-FIA`, `CPO-CSO-MTD`, `FRC-CLA-ASF`).
  `test_profile_traceability.py` checks every source against the pinned
  schema and dataset, so a field cannot claim a requirement that does not
  exist. Three fields with no FedRAMP source (`management_plane`,
  `federal_information_types`, `evidence_retention`) are removed and the
  test asserts they stay removed. The AWS partition, regions and IaC
  technology remain as operational inputs the generators print; they are
  never blockers.
- **`sdr.py init` asks every required question.** The wizard asks the
  contract's questions in plain English with the FedRAMP source beside each,
  the class-conditional blocks for the class just answered (`FRC-APP-FIA`,
  `CPO-CSO-OSA`, `CDS-CSO-AVR` and `CPO-CSO-MTD` for B and C; `FRC-CLA-ASF`
  for A; `FRC-APP-FCP` for all), contacts as name, email and phone, the
  business category against the schema's 36-value enum (`list` prints it;
  free text is refused), and ends by listing exactly what is still missing.
  `--set key=value` takes dotted paths for nested answers; `--non-interactive`
  applies them without prompting. Preflight blocks on the same list through
  the same module, so the wizard and the gate cannot disagree.
- **One place per fact.** `build_cpo.py` derives the 16 `CDS-CSO-PUB`
  public-information items from the profile fields that already carry them
  (package id, service and deployment model, contacts, website, logo,
  description, SCG and trust-center links, next OCR date, assessor and id);
  a typed `cpo_required_information["CDS-CSO-PUB"]` value wins only when it
  is real. Contacts are structured (`{name, email, phone}`, a plain string
  still accepted) and reach the CPO's `contactInfo` members with the phone
  normalized to the schema's `###-###-####`; a free-text business category is
  kept out of the schema member and recorded as an unresolved assumption,
  which `package-preflight` blocks on. The CPO, SDR text, SCG and reviewer
  package share one title helper and one resolved CPO URI, so the
  consistency validator compares like with like.
- **Fixtures follow the contract.** The readiness harness's "fully filled"
  Class C fixture never set `business_purpose`, used a free-text category and
  typed a `CDS-CSO-PUB` block that contradicted the profile (PaaS vs SaaS,
  two FedRAMP IDs, two UEIs); it now fills the contract and types no public-
  information block, so the READY path also proves the derivation. Its four
  `CDS-CSO-PUB` probes attack the source fields the builder reads. The
  AUD-F38 preflight before/after plants its own Example fixture in a temp
  copy instead of relying on the template to ship one.

The Class B sample's gate, run as documented (`AUD-F39`, High, with a killed
mutation):

- **A content minimum binds at the class the offering submits (AUD-F39).**
  Since `sdr.py build` regenerates the inactive classes from the live record
  store, the A/B/C class matrix validates one store under three classes. The
  validator made a MUST shortfall on populated records a hard failure wherever
  the validated class was C, so a populated Class B offering, with exactly the
  one automated method per KSI that FRC-CSX-VVK asks at Class B, failed
  `sdr.py validate` on the Class C matrix run with 46 "hard failures" for a
  class it never claimed. Reproduced at `e3b28a6` with
  `examples/sample-offering/build_sample.py`: Build gate PASS, then
  `FAIL. validate_sdr.py class C exited 1`. In an inactive-class run the
  FRC-CSX-VVK minimum and the evidence-linkage expectation are now reported as
  ADVISORY, naming the class the offering submits at; at the submitted class
  they stay hard, and every structural, schema and dataset-fidelity check
  keeps its force in every class.
- **Suites that describe the template no longer measure a provider's
  profile.** The wizard tests build their fixture from the contract instead of
  copying the live profile; the traceability test's template-only section runs
  while `organization_name` is unanswered and says so otherwise. Both had
  failed under any filled profile (the sample's, or a provider's whose
  assessor is named "Example ..." or who set `sdr_last_updated`, which the
  scanner asks for and the contract now declares optional).
- **Every FRC-APP-FCP blocker cites the rule**, including the one for a
  `provider_verified_at` value that is not a timezone-aware ISO-8601 datetime.
- **The 30-day window test uses the UTC day the derivation uses.** Its fixture
  ended on the host's local date, one day short of the window every US
  evening; the same code passed in the UTC runner and failed locally.
- **The Class C sample restores the review register from its backup**, like
  every other input, instead of `git checkout`, which discarded a provider's
  uncommitted sign-offs and needed a git checkout to exist.
- The committed Acme sample inputs and generated package are regenerated from
  the contract-following builder, so running the sample as documented leaves
  the tree byte-identical.

## 1.5.0, 2026-10-05

Pinned dataset: `2026.09.13.02` (unchanged)

Release governance, telemetry truth and the evidence truth model. A
twenty-finding review of the `1.4.0` release concluded that the FedRAMP
interpretation (the A/B/C rule profiles reconcile exactly against the raw CR26
dataset; the 46-KSI catalog and the five optional-at-B indicators are right) was
no longer the weak point, and that the evidence truth model and release
governance were. This release closes all sixteen findings of that review, the
three findings of the 2026-09-26 end-to-end audit of `2f72a15` (`AUD-F26` to
`AUD-F28`), the six items of the 2026-10-05 SAS delivery review of `cb23eb7`
(`AUD-F29` to `AUD-F37`), and adopts the September 2026 in-place updates to five
official FedRAMP schemas. It supersedes `1.4.0`, which was published by hand
from a red audit-gate with an unsigned tag; this version is published only
through the tag-driven release workflow (`release.yml`), which refuses an
unsigned tag and re-runs the whole gate on the tagged commit. No dataset change;
no change to any rule statement, force, timeframe or KSI applicability. Entries
are newest first.

Attested metric history (SAS delivery review of `cb23eb7`, item 6, and the
production-assurance profile of the 16-item verdict's finding 16; `AUD-F37`,
with a killed mutation):

- **The metric history can no longer be filled in after the fact unnoticed
  (AUD-F37, Critical).** Every observation the appender writes is hash-chained
  to its predecessor (or the KSI's pruning anchor) and carries the collector's
  `run_id` and the digest of the facts store it came from. `history_digest()`
  over every chain head is one value a separate signer attests:
  `publish_history.py publish --sign-key-arn` writes `meta.history_signature`
  and `package-preflight` verifies it offline against the independently pinned
  `expected_evidence_signer`. At Class C/D an edited, inserted or deleted
  observation, a bad anchor or a series point with nothing behind it is a
  blocker under every profile. New offering field `evidence_store_profile`:
  `development` (template default) reports unchained, unattested or unsigned
  history as advisories; `production-assurance` makes them blockers; an
  unknown value blocks. The FRC-CSX-VVK binding gate now counts a declared
  method as working only when its series carries a datapoint inside its
  cadence window, so "two working automated methods" can no longer be met by
  a series that exists but stopped, or was typed in with old dates.
  Assessor-attack probes for every tamper (backfill, edit, delete, stale
  method, unsigned production, rechained tamper with a forged signature) block;
  a production-assurance history with a valid signed digest stays READY.
  Histories written before this release carry no chain fields and are reported
  as unchained (advisory under development) until the collector re-accumulates.

Word-document integrity and sample residue (SAS delivery review of `cb23eb7`,
items 1 and 5; `AUD-F35`, `AUD-F36`, each with a killed mutation):

- **The Word document is byte-reproducible and inside every integrity check
  (AUD-F35, High).** `build_docx.py` rewrites the saved container with fixed
  zip entry timestamps, attributes and deflate level, and stamps the core
  properties with the pinned dataset's date instead of the wall clock. The
  `.docx` is now fingerprinted in the release manifest (so the bundle
  assembler ships the exact checked bytes), hashed by both reproducibility
  gates and diffed without exclusion in CI, the AWS buildspec and the Actions
  loop. It had been excluded from all of them, while the README said the
  human-readable outputs could not silently drift. BREAKING for anyone who
  hand-edited a committed `.docx`: the regenerate-and-diff gate now fails on it.
- **One build definition regenerates every class, Word documents included
  (AUD-F36, High).** New `build_inactive_classes.py` step of `sdr.py build`
  rebuilds each inactive class's SDR JSON, text and `.docx` before the active
  class; the CI per-class loop is removed. Both sample builders back up and
  restore the validation reports they overwrite. Running the Class C sample as
  documented had left the fictional offering in the committed Class C `.docx`
  409 times; an end-to-end regression now runs the sample and asserts every
  committed deliverable is byte-identical afterwards.

Fail-closed collection loop and dependency audit (SAS delivery review of
`cb23eb7`, 2026-10-05, items 2, 3, 4 and the "third-party components unknown"
gap; every item reproduced before fixing; `AUD-F29`..`AUD-F34` in the defect
ledger, each with a killed mutation). Together the four small items let a
provider run the loop as documented for six months, see green everywhere, and
arrive at submission with evidence that is missing, discontinuous or empty:

- **A collection that observed nothing is a failed run (AUD-F29, High).**
  `collect_facts.py` tallies evaluated vs unevaluated vs errored facts into the
  facts store meta (`collection_outcome`) and exits 4 when NO check produced an
  evaluated outcome (every API denied, wrong region, expired role). It used to
  exit 0 with every fact in `ERROR`.
- **An empty append does not look like maintenance (AUD-F30, High).**
  `append_metrics.py` records every run under `meta.last_attempt` but advances
  `meta.last_run` only when at least one datapoint was appended, and exits 4
  on an empty run. It used to stamp `last_run = today` and exit 0.
- **The GitHub Actions loop persists the history (AUD-F31, Critical).**
  `living-sdr-loop.yml` now REFUSES to run without the
  `SDR_METRIC_HISTORY_BUCKET` repository variable, restores the durable
  history before appending and publishes it back with compare-and-swap
  (the AWS buildspec's loop). It used to append to a git-excluded file on an
  ephemeral runner and discard it every night.
- **Failed collections raise an alarm (AUD-F32, High).** The AWS template gains
  an EventBridge rule on failed, faulted, timed-out or stopped builds of the
  collector and drift-check projects (the pipeline-state rule never saw them);
  the Actions loop files, or comments on, a GitHub issue on any failure.
- **Staleness is reported before it blocks (AUD-F33, Medium).**
  `package-preflight` adds an ADVISORY for every in-scope KSI whose newest
  datapoint is older than 7 days (`MOT_STALE_ADVISORY_DAYS`, project policy),
  distinct from the 45-day continuity bound that was the only signal.
- **The locked dependency closure is audited for known vulnerabilities
  (AUD-F34, High).** `pip-audit` (2.10.1, `--require-hashes --strict` on
  `requirements.lock`) is a HARD step of the single release-gate security
  section, so CI, the AWS release build and `sdr.py release` run it
  identically. Its first run found 14 advisories across two pins:
  `cryptography` 46.0.3 -> 50.0.2 and `aws-cdk-lib` 2.251.0 -> 2.253.0, lock
  re-resolved with the Makefile recipe, SBOM regenerated, audit now clean.

Evidence-path hardening (external end-to-end audit of `2f72a15`, 2026-09-26;
three findings, all reproduced with the public helpers before fixing;
`AUD-F26`..`AUD-F28` in the defect ledger, each with a killed mutation):

- **The evidence digest now binds the whole displayed assertion (AUD-F26,
  High).** `xEvidenceContentHash` (and therefore the KMS signature over it) is
  computed over `evidence_wiring.canonical_payload(entry)` - evidenceType,
  evidenceDescription, evidenceLocation, evidenceText, lastUpdated and the
  sanitized xSourceFact - instead of the sanitized fact alone. Rewriting
  `evidenceDescription` beside a "verified" digest previously stayed
  `verified`; it is now a HARD `INTEGRITY FAILED`. The legacy inline
  `source_fact` shape (digest over the raw fact only) can only reach a
  readiness finding, never `verified`, and is HARD under a signing-required
  signer. The fail-closed "hash implementation missing" check runs before
  source resolution. BREAKING for hand-built evidence entries: produce them
  with `fact_to_evidence` (the readiness sample and attack tests now do).
- **Account scopes never collide and the account never leaks (AUD-F27,
  High).** An account-tagged fact carries an opaque `scope` (HMAC-SHA256 under
  the deployment-private `SDR_EVIDENCE_SCOPE_KEY`, or a caller-supplied
  slug-safe alias that may not be the account itself) in the signed payload and
  the evidence object key, plus the collector `run_id`. Two accounts' opposite
  findings for the same service/check/region were previously collapsed onto
  one pointer and the second (a FAIL) silently dropped by `attach_evidence`;
  both now survive with distinct pointers and digests, de-duplicated on
  (location, scope, observation). A fact tagged with an account but no way to
  derive a scope is REFUSED (`EvidenceExportError`), never dropped or exported.
  `collect_multi_account.py` stamps `run_id`/`scope` on every fact, exposes
  `scope_map()`, and `--out` writes facts plus the PRIVATE scope -> account map
  to the git-excluded facts store (an assessor's key to account-level coverage).
- **Free-form detail cannot carry identifiers into the package (AUD-F28,
  Medium).** `detail` and `status` are scrubbed (ARN, access key, key
  material, email, URL, IPv6, IPv4, account id, hostname, long opaque token)
  and length-bounded before entering an entry; object-key segments (service,
  check, region, scope, run_id) must be slug-safe. First-party collector detail
  strings are unchanged by the scrub (a regression proves it). The
  generated-bundle sensitive gate additionally flags IPv4/IPv6 addresses, ARNs
  and internal hostnames as an independent backstop.

Upstream schema adoption (no dataset change; no rule statement, force,
timeframe or KSI applicability changed):

- Adopted the September 2026 in-place updates to five official FedRAMP JSON
  schemas, verified byte-for-byte against fedramp.gov on 2026-09-26:
  common-definitions `0.3.0 -> 0.4.0` (adds a reusable
  `$defs/contactInformation` object), Certification Package Overview
  `0.1.4 -> 0.1.6` (adds an OPTIONAL top-level `advisors` array), and
  version-string-only bumps to Ongoing Certification Report `0.2.0 -> 0.2.1`,
  Incident Report `0.2.0 -> 0.2.1` and Significant Change Notification
  `0.1.2 -> 0.1.3`. Nothing required was added, so every previously valid
  document stays valid; the generated CPO and OCR re-validate against the new
  schemas. `pinned_schema_version_guard`, `references/sources.lock.json` and the
  release manifest now carry the new versions and hashes. The SDR schema
  (`1.1.1`), the CR26 dataset and rules schema, and the VER-family schemas are
  unchanged upstream.
- `update_sources_lock.py` now refreshes EVERY pinned entry from the file on
  disk (sha256, and `$schemaVersion` for JSON schemas), fails closed on a
  missing pinned file, and stamps `verified_current_on` only when the caller
  asserts `--verified-on`. A schema adoption is therefore a copy plus one
  command, never a hand-edited hash. Tests in
  `validation/scripts/test_update_sources_lock.py`.

Fixed:

- Daily drift check aborted on the first non-dataset drift. In `check()`, the
  line `[ "$NAME" = "CR26-dataset" ] && DATASET_CHANGED=1` was the function's
  last command, so under `set -e` any drifted source other than the dataset made
  `check()` return 1 and killed the step. The 2026-09-26 run reported only the
  common-definitions drift, never reached the remaining seven sources or the
  changelog check, and filed issue #188 with an empty title because the `drift`
  output was never written. Replaced with a plain `if`; the issue step now runs
  only when the check step actually recorded drift, so a download failure fails
  the run without filing a false "sources changed" issue.

Release governance and telemetry truth (the first half of this release, merged
2026-09-24 to 2026-09-25 as PRs #178 to #187 against the twenty-finding
review's items 1 through 15; the review's item 16, the production-assurance
profile, is the attested-history entry above):

Release governance:

- One release gate. `audit/release_gate.py` is the single definition of the
  audit and security sections; the CI `audit-gate` and `security-scan` jobs, the
  AWS `RELEASE_MODE` build and `python sdr.py release` all execute it. A new
  `release-gate` aggregate job depends on `validate`, `audit-gate` and
  `security-scan`, runs even when one failed, and is the single required status
  check on `main`. Before this, only `validate` was required, so a red
  audit-gate did not block a merge, and `sdr.py release` ran neither the audit
  gate nor Bandit (AUD-F12).
- Tag-driven publication. `.github/workflows/release.yml` refuses a lightweight
  or unsigned tag and a tag that does not equal the committed manifest's
  `release_tag`, re-runs the whole validate workflow on the tagged commit, and
  attaches the release manifest, the release attestation, the SBOM and the
  active-class bundle as release assets. `sdr.py release` now instructs
  `git tag -s`, matching `docs/versioning.md`.
- Mutation gate integrity. A skipped mutation (target text absent) now fails
  the gate instead of passing it, so a refactor cannot silently disarm a closed
  defect's protection (AUD-F13). The runner reconciles the defect ledger: every
  CLOSED, mutation-verified defect must map to exactly one executed, killed
  mutation and every mutation to such a defect (AUD-F14). The verdict is a pure
  function so each rule is tested in isolation, and restore writes the saved
  original bytes back rather than `git checkout`-ing over a dirty local tree.

Telemetry truth model (Class C metrics):

- Pagination. Every AWS list/describe call walks every page (botocore paginator
  when one exists, continuation token by name otherwise); a page-cap hit yields
  `OBSERVED_PARTIAL` with no ratio and is never scored (AUD-F15). Previously KMS,
  CloudFormation, Config, WAF, EC2, ECR, IAM, CodePipeline, DynamoDB, Backup and
  Access Analyzer read one page, several of them into a measured/total ratio.
- Coverage. Ratio facts carry `scope_total`, `evaluated_total` and
  `unknown_total`; unreadable resources stay in scope as unknown instead of
  vanishing from the denominator. A fact whose evaluated coverage is below the
  project floor (`MIN_EVALUATED_COVERAGE` = 0.95; an offering may tighten it via
  `telemetry_min_coverage`) is withheld from scoring, never scored as a
  failure, and named in the datapoint's `coverage_gaps`; the datapoint carries
  aggregate coverage. Only a response that establishes absence
  (`NoSuchPublicAccessBlockConfiguration`, `NoSuchLifecycleConfiguration`) is
  evaluated (AUD-F17).
- Routing by check. Every `METRIC_SOURCE_MAP` route is `service:check`; a bare
  service key is refused by the metric engine, prefill and `append_metrics`.
  Least privilege is measured by `accessanalyzer:active_findings` (a scored
  binary: zero active findings), never by analyzer presence; recovery testing
  routes `backup:restore_testing` only; data removal routes `s3:lifecycle` and
  `dynamodb:ttl`; resource integrity routes `cloudtrail:log_validation` and
  `ecr:image_immutability` (AUD-F16). The collector registry is regenerated.
- Non-destructive history. A second run on the same day no longer replaces the
  first. Every run is appended as an immutable timestamped observation under
  the KSI (retention-pruned) and the day's series point is the conservative
  rollup of that day's runs (worst passing fraction) with `runs`,
  `min_fraction` and `max_fraction`; per-metric series roll up the same way
  (AUD-F19).
- Compare-and-swap publish. `automation/metrics/publish_history.py` replaces
  the blind `aws s3 cp` down/up of `metric-history.json`: restore remembers the
  ETag, publish uses `If-Match` (`If-None-Match: *` on first run), a 412 exits 3
  and the collect buildspec retries restore, append, publish a bounded number
  of times. Every run's observations are archived append-only under
  `metrics/observations/<date>/<run>.json` (AUD-F20).
- Real method binding. `automation/metrics/method_ids.py` is the one identity
  for a verification method (registry `check_id` for a Config rule,
  `posture:<service>:<check>` for a collector check). The metric engine keys
  per-method series by it and `prefill_from_facts.py` now emits structured
  `{method_id, method, automated: true, cadence, ...}` records with it, so the
  real collector -> history -> prefill -> preflight path binds; plain-string
  tests counted as zero automated methods. A new end-to-end test drives the
  production code through fake AWS clients and asserts every prefilled method
  binds; it caught `cloudtrail:siem_capture` declaring a method that could
  never bind, which is now a scorable binary (AUD-F18).
- The FRC-CSX-MOT continuity tolerance is explicit project policy.
  `mot_max_gap_days` (default 45 days, ceiling 90) is documented as a repository
  bound, not a FedRAMP figure, is declarable in the offering profile for
  assessor review (an invalid value blocks rather than silently defaulting), and
  every preflight message names it as such. The comment that claimed a
  4x-median adaptive tolerance the code never applied is gone (AUD-F21).
- Supply chain: `requirements.lock` is a resolver-generated (uv, linux/py3.12),
  fully hashed 27-package closure of `requirements.txt` + `requirements-ci.txt`;
  every workflow and buildspec installs with `pip install --require-hashes -r
  requirements.lock`, and the SBOM is now that resolved closure with per-package
  hashes (AUD-F25). The requirements oracle independently re-derives the per-class
  FRR set, force, statement and timeframes and the enumerated Class A set from the
  raw dataset (41 / 158 / 158, reconciled clean; AUD-F22); `sdr.py validate` runs
  the authoritative validator for every supported class, which surfaced and
  fixed three example KSIs that were invalid at Class C (AUD-F23); a parity test
  that compared 0 against 0 now reads the real report key (AUD-F24).
- The implementation guide's worked Class C example now uses the structured
  automated-method shape the validator counts and explains `method_id`
  binding; the two plain strings it showed counted as zero methods.

Correction to the `1.4.0` record: the `1.4.0` release notes state a mutation
suite result of 10 killed / 0 survived. The CI run on the release commit
(`c7d43bd`) reported 9 killed / 1 survived (MUT-F10, the stale-bytecode false
survivor fixed in the entry below) and its audit-gate was red when the release
was published; the tag was unsigned and no assets were attached. The 10/0
figure came from local clean-room runs, not from the release commit's CI. The
release is left in place and superseded; its GitHub release notes carry the same
correction.

Post-`1.4.0` fixes folded into this release:

- The mutation runner (`audit/mutation_tests.py`) now purges every
  `__pycache__` before each mutated test run and forbids bytecode writes during
  it, and restores each mutated file byte-exactly with verification. Python
  trusts a cached `.pyc` when the source's size and mtime-in-seconds match; a
  length-preserving mutation (MUT-F10, 50 to 50 characters) that landed in the
  same second as a cache compiled from the original was therefore run as the
  ORIGINAL bytecode, and the audit gate reported a false SURVIVED on `main`
  (validate-sdr run 35993242564, twice). New `audit/test_mutation_runner.py`
  arms that exact trap, proves a bare run is fooled by it, and asserts the
  runner still kills the mutation; it is wired into the audit-gate job as a
  hard gate. No framework behavior, rule, or dataset change.
- The submitted SDR's daily-data window ceilings use the UTC calendar day, the
  same clock the collectors stamp datapoints with (F11, PR #178).

## 1.4.0, 2026-09-24

Pinned dataset: `2026.09.13.02`

Hard-mode audit remediation and an anti-circular-verification gate. Closes a
ten-finding builder/adversarial audit (six High, four Medium) against the CR26
`2026.09.13.02` dataset, adds two provider-integration features, and makes the
audit itself machine-enforced so a regression cannot silently return. No dataset
change and no architecture change; every fix tightens an existing gate or
corrects a reviewer-facing report, shipped CI-green with a regression that fails
on the old code and a mutation that proves the regression can detect the defect.

Metric-engine and evidence-outcome integrity:

- History is keyed by `(rule, region, account)`, so a later region can no longer
  overwrite an earlier region's result and hide a `NON_COMPLIANT` behind a
  `COMPLIANT` (F04).
- A stale fact replayed on a later run is no longer stamped as fresh; ingestion
  time and observation time are kept distinct (F05).
- Corrupt existing metric history is rejected rather than silently treated as a
  first run and overwritten (F07).
- Posture facts route by `(service, check)`, not service alone, so an unrelated
  same-service check can no longer score an unrelated KSI, and each check keeps
  its own metric identity (F03).
- A collector permission error (AccessDenied, throttling) is recorded as
  unmeasured, not as a negative outcome; only a genuine "no encryption
  configured" API response counts as a real negative (F08).
- A bounded Inspector sample with more pages available is reported as partial and
  scores nothing, instead of claiming full coverage from the first 100 records
  (F09).

Signing, verification-method binding, and clock consistency:

- Under a required signer, an unresolvable evidence source is a hard finding; the
  soft-finding early return no longer precedes the signing check (F01).
- Id-less automated verification methods are uncountable and unbindable rather
  than counted by text; the count and binding gates share one identity (F02).
- The metric-over-time continuity check measures the leading gap from the window
  start, so a series clustered near today can no longer pass a long window (F06).
- All preflight date windows read one UTC clock (`_utc_today()`) instead of the
  host's local date, so the same code and fixture cannot pass in CI (UTC) and
  fail on a machine west of UTC (F10).

Provider-integration features:

- `sdr.py init` is a plain-English offering-profile wizard (company, offering,
  class, regions, contacts, URLs), scriptable with `--set` and validated, that
  never mutates a tracked file.
- A custom AWS Config-rule importer maps a provider's own rules to KSIs through a
  gitignored `customer-config-rules.json` overlay with no code edit; the template
  stays secret-free and the registry restores byte-for-byte when the overlay is
  removed.

Anti-circular-verification gate:

- A mutation runner (`audit/mutation_tests.py`) re-introduces each of the ten
  closed defects into production code and asserts its named regression test goes
  red; a surviving mutation fails the build. It caught a real blind spot during
  the audit: the first F10 regression never exercised the UTC clock, so a
  dedicated behavioral test was added and verified to detect the mutation.
- A requirements-differential oracle (`audit/requirements_oracle.py`) reconciles
  an independent dataset traversal against the production applicability engine.
- Both run as hard gates in GitHub Actions (`audit-gate`) and on the AWS
  CodeBuild release path, and a permanent `audit/defect-ledger.json` records every
  finding with its fix, regression test, and mutation.

## 1.3.1, 2026-09-23

Pinned dataset: `2026.09.13.02`

Audit-remediation patch release. Closes the KMT-layer audit and the detailed
repo audit (F-01 through F-09) against the CR26 `2026.09.13.02` dataset. No
dataset change and no architecture change; every fix tightens an existing gate
or corrects a reviewer-facing report, verified against the pinned dataset and
shipped CI-green with an adversarial or negative test that fails on the old code.

Metric-engine truth and routing:

- `OBSERVED` posture no longer counts as passing; a measured `0 / N` contributes
  as a real negative observation rather than inflating a metric.
- Explicit negative posture (`NONE` / `NOT_ENABLED`) is scored `(0, 1)` instead of
  being dropped, so a disabled control cannot silently vanish from the denominator.
- Metric routing is bound to an explicit per-KSI `metric_service_keys` allowlist
  rather than substring-matching AWS service names in narrative prose, closing the
  fan-out where an unrelated posture could accumulate history against a KSI.
- Config-rule vocabulary is allowlist-checked and a bogus Aurora rule was removed.

Verification-method binding (FRC-CSX-VVK):

- Automated-method counting is set-based against the class minimum and counts only
  distinct structured methods, not raw test strings.
- Class C requires each declared automated method to be bound to observed per-method
  telemetry; two declared but one bound blocks, rather than clearing existentially.
  The binding stays active under the initial-certification MOT exception.
- The reviewer-facing assurance graph now uses the exact same automated-method
  counter as the authoritative validator (shared `verification_methods` module), so
  `evidence-coverage.json` can no longer report the VVK minimum as met when the
  validator says it is not.

Class B scope and process/document KSIs:

- The Class B optional-KSI scope (41 baseline, 5 optional excluded unless selected)
  is unified across the builder, validator, scanner, assurance graph, and preflight
  via a single `submitted_ksi_ids` resolver; an unknown optional selection now blocks.
- The 11 document/process KSIs carry provider-deployed outcome-metric contracts rather
  than pretending an AWS API can assess organizational-process effectiveness.

Harness, supply chain, and reproducibility:

- The readiness fixture suite generates into a temporary directory so a validate run
  leaves the worktree clean.
- The scanner treats legitimate JSON metadata citations as present, not drift.
- `make install` and `setup.py` install from `requirements.txt` (including
  `cryptography`), with a drift-guard test so the install list cannot silently omit a
  pinned dependency.

## 1.3.0, 2026-09-20

Pinned dataset: `2026.09.13.02`

Assurance-hardening release. Closes an external re-audit and a fresh acceptance
audit against the CR26 `2026.09.13.02` dataset, tightening the submission-readiness
gates so a structurally complete but content-free or wrong-scope package can no
longer reach ready. No dataset change; the v1 architecture remains frozen. Every
change was verified against the pinned dataset and shipped CI-green.

Readiness and semantic correctness:

- Normalized the `package-preflight` status path so an authoring status of
  `Planned`, `Gap`, `Exception`, or `Needs validation` is evaluated as the official
  `Not Implemented` it maps to, closing a false-ready path where a raw authoring
  status read as answered. Pinned the human-readable and JSON status normalizers
  with a parity test.
- Required the per-metric "summary of each metric" breakdown for multi-metric KSIs
  at Class B, C, and D (`SDR-CSX-KMT`), so a genuinely multi-metric indicator can no
  longer collapse into a single aggregate. Unified the KMT summaries to a single
  source derived from the durable metric history rather than hand-authored duplicates.
- Made `SDR-CSX-KMT` historical-metric summaries a `package-preflight` blocker at the
  classes where they are a MUST (Class B: 30-day and up-to-one-year; Class C and D:
  those plus the actual daily metric data derived from history; the external
  `dailyDataReference` URL is optional). Bounded all metric series against future-dated
  observations.
- Modeled non-implementation as reason AND resulting customer risk for a not-followed
  `SDR-CSO-FRR` rule and a no-measures `SDR-CSX-KSI`, carried end to end through the
  record store, preflight, JSON SDR, and human-readable SDR.
- Hardened `package-preflight` against content-free submissions: an `_is_hollow`
  predicate rejects bare non-answer tokens (`N/A`, `none`, `.`, `unknown`, and the
  like) in addition to `TBD`/empty/placeholder, while a justified `N/A: <reason>`
  still passes. Applied to the CPO structured required-information members,
  `CPO-CSO-OSA` summary, required offering-profile fields, `FRC-APP-FIA` assessor name
  and Recognition id, Sales/Security contact names, `CPO-CSO-MTD` metadata, and the two
  gate-unblocking conditions (`FRC-CSX-MOT` initial-certification exception narratives
  and the `FRC-APP-USA` freshening reviewer/id/reference). Date, URI, and hash fields
  keep the narrower placeholder test.

Artifacts and optional-rule scope:

- Replaced the substring artifact heuristic with a REQUIRED / REQUIRED_ONE_OF /
  CONDITIONAL classifier, so a mandatory one-of artifact (`report OR sample report`)
  is gated rather than demoted to advisory. This newly gates the mandatory one-of
  artifact rules per class that were previously treated as optional.
- Generalized optional Class A review so any selected MAY rule inherits its
  rule-specific artifact obligation, and required a selected Class A `SDR-CSX-KMT` to
  carry actual in-window historical metrics rather than an empty placeholder.
- Enforced the selected Class A `IVV-CSO-FIA` annual FedRAMP Recognized independent
  assessment (identity plus date within the past year) and emitted an
  `xIndependentAssessmentSummary` IV&V block into the B/C SDR metadata, threading the
  active build class so the block is not wrongly emitted for Class A.
- Rendered the Independent Assessment Summary in the human-readable SDR to mirror the
  JSON metadata, with a parity test pinning both renderers.

Evidence, isolation, and security:

- Cryptographically verify evidence signatures offline (ECDSA) against an
  independently-pinned trusted signer instead of trusting the key id carried in the
  evidence object; a signing-required mode blocks a silent downgrade to hash-only.
- Content-addressed evidence ingestion with S3 VersionId provenance and verify-by-exact-
  VersionId.
- Made the evidence-store isolation reference stack access logging real and its keys
  content-addressed and append-only; enforced TLS-only bucket access; split the
  Object Lock deny statement so object-level actions target the object ARN and the
  bucket-level action targets the bucket ARN.
- Hard-gated Bandit in CI at medium severity / medium confidence (no `|| true`).
- Added a standing assessor self-attack harness that probes the three assessor
  archetypes (gate != deliverable, narration != enforcement, optional != absent) on
  every build.
- Derived the scanner's `FedRAMP pending` KSI status from the dataset (honoring
  `varies_by_class`) instead of a hardcoded list.

Samples, docs, and robustness:

- Added a fully-worked fictional Class C sample and an assessor-attack harness under
  `examples/sample-offering-class-c/`. The sample fills a complete Class C package and
  drives it to `package-preflight`; `--attack` tampers the ready package one hollowing
  edit at a time and asserts each is blocked while a justified `N/A: <reason>` stays
  ready.
- Fixed a human-readable render crash on structured `tests` entries: `build_sdr.py`,
  `build_docx.py`, and `explain.py` coerce a structured test entry to readable text,
  so a malformed test surfaces as a clear schema message rather than a `TypeError`.
- Corrected the README CI wording (Bandit is a hard CI gate; ASH and Fortify remain a
  local pre-commit gate), documented that Class A historical KSI metrics are suppressed
  unless `SDR-CSX-KMT` is selected, and corrected stale Class C daily-data and
  `CPO-CSO-OSA` scope wording.

## 1.2.0, 2026-09-14

Pinned dataset: `2026.09.13.02`

Maintenance release adopting the FedRAMP CR26 upstream update published 2026-09-13.
Triggered by an authoritative source change, not by feature work; the v1 architecture
remains frozen.

- Refreshed the pinned CR26 dataset and its structure schema from `2026.07.14.01` to
  `2026.09.13.02` (upstream commit `58487bda`), re-locked in `sources.lock.json`. The
  update added timeframe range fields (`timeframe_num_min`/`timeframe_num_max`, e.g. on
  `CCM-QTR-SAR`), top-level timing on six rules, and the force-of-rule definitions
  `FRD-MAY`/`FRD-MST`/`FRD-MNT`/`FRD-SHD`/`FRD-SNT`. No rules were added or removed.
- Made the rule catalog a lossless projection of top-level timing, including the new
  min/max range pair, so richer official timing semantics are preserved through
  catalog and class profiles rather than silently dropped.
- Expanded `dataset_diff.py` to report timeframe, artifacts, following-information,
  `varies_by_class`, and FRD definition add/remove/change deltas, with adversarial
  tests for the range and definition cases.
- Fixed a collector/evidence timestamp mismatch: the live collector emits
  `collected_at`, which the evidence sanitizer allowlist and timestamp resolution now
  preserve, so `lastUpdated` is populated and the digest covers the timestamp.
- Made the evidence-integrity validator fail closed: if the canonical hash
  implementation cannot be imported, a resolvable evidence entry is a hard failure, not
  a soft finding.
- Storage: a dry-run against a nonexistent bucket with explicit `--retention-days` now
  reports a plan without querying lifecycle on the never-created bucket.
- Documentation sync: corrected stale "two read-only AWS calls" / "one editable
  surface" descriptions, the pinned dataset version references, the build-gate verdict
  wording, and unpinned install samples.

## 1.1.0, 2026-09-13

Pinned dataset: `2026.07.14.01`

This release freezes the v1 architecture. The
theme is a strict, class-correct submission-readiness engine and an explicit trust
boundary from authoritative FedRAMP sources through to human signoff and preflight.
No new subsystem, agent, evidence model, or package format was introduced; these are
correctness and hardening changes grounded verbatim in the pinned CR26 dataset.

### Added

- `validate_upstream.py`: validates the pinned dataset against the official rules schema and verifies both the dataset and rules-schema lock hashes; wired as build step 1 and into the daily drift check. `update_sources_lock.py` refreshes both lock entries atomically.
- Field-level submission readiness: `SDR-CSO-FRR` (7 required items) and `SDR-CSX-KSI` (5 required items) are each gated individually; a justified `N/A` counts, a bare `N/A` or a `TBD`/placeholder does not.
- Class A applicability throughout: preflight, the assurance-graph builder, and its validator all resolve Class A to its 7 CLA-enumerated KSIs; the CPO required-information set intersects `CPO-CSO-OVR` with the resolved class rule set (Class A carries only `CDS-CSO-PUB` + `MAS-CSO-IIR`); the `CPO-CSO-MTD` metadata gate is class-aware.
- Structured CPO semantic completeness: `CDS-CSO-PUB`, `CDS-CSO-IRP`, and `MAS-CSO-TPR` are validated against the CR26-enumerated members, so a bare sentence no longer satisfies a rule that enumerates concrete items. `validate_cpo_semantics.py` independently derives the expected `CPO-CSO-OVR` rule set from CR26 and hard-fails on a missing or extra entry.
- Class A external assessment (`FRC-CLA-ASF`/`FRC-CLA-EAM`): the framework is checked against the approved allowlist (FedRAMP Rev5/Ready, SOC 2 Type II, GovRAMP) and the framework-specific material checklist is enforced.
- Recognized-assessor identity: `FRC-APP-FIA` requires the assessor's FedRAMP Recognition id; `FRC-APP-USA` freshening requires a Recognized reviewer id and a valid `reviewed_at` date on or after the original assessment.
- `FRC-CSX-MOT`: availability survivability (`CDS-CSO-AVR`) is a B/C blocker; entirely-missing KSIs are detected; the initial-certification exception is modeled with an explicit boolean+description contract in the profile and enforced in preflight.
- Signoff input binding: the release manifest hashes the authoritative provider inputs (offering profile, records store) alongside generated artifacts, so a post-signoff input change invalidates the manifest-bound signoff.
- Evidence sanitization: `xSourceFact` is an allowlisted projection and the integrity digest is computed over that same projection, so recompute stays verifiable without over-exposing environment detail.
- The CodeBuild pipeline exports the complete Certification Package (`package/**` plus the release manifest), not an SDR-only subset.
- `automation/exporters/oscal_export.py`: an OSCAL export of the Security Decision Record. It reads a generated SDR JSON and emits an OSCAL Assessment Results document alongside it (`sdr/json/sdr-class-<x>.oscal.json`), so the same verified facts are available in the machine-readable interchange format that agency governance, risk, and compliance tools ingest. It is a pure read-transform-write adapter: it never queries AWS, never runs a determination, passes every status through verbatim (`Not Implemented` stays `not-satisfied`), never invents satisfaction, and skips `TBD` evidence rather than emitting a fake resource. Wired into the build pipeline and `sdr.py`; 7 offline tests. See `docs/oscal-export.md`. The export makes no claim about whether any FedRAMP process requires OSCAL; it simply provides the option.
- `automation/collectors/evidence_wiring.py`: turns read-only collector facts into schema-valid `ksiEvidence[]` entries (populating the official schema's existing `evidenceType`/`evidenceDescription`/`evidenceLocation`/`evidenceText` fields) so the SDR's evidence array is fed from telemetry instead of left empty. It never changes a status, and when it cannot know the durable artifact URI it emits an obvious `sdr://` placeholder for a human to replace rather than fabricating an https link. 9 offline tests.
- `examples/shift-left/`: a policy-as-code pre-deploy gate sibling to the SDR framework, matching the AWS Security Assurance Services compliance-engineering demo. An OPA/Rego rule and an equivalent CFN Guard rule enforce S3 TLS-in-transit against terraform-plan JSON; a local runner uses `opa` if present and otherwise a pure-Python evaluator of the same rule, with pass-is-silent / fail-blocks semantics, an `--alert` dev mode, and optional JSON evidence output. It never writes to the record store or sets an SDR status. 8 offline tests.
- `docs/references/oscal-and-machine-readable-packages.md`: a distilled, sourced reference note recording OSCAL context (the 2022 AWS OSCAL SSP milestone and RFC-0024) with primary-source links. (A companion compliance-engineering control-model reference was later internalized and removed from the public repository; see 1.2.0.)

### Changed

- `submission ready` is now strict and field-level rather than satisfied by a populated implementation field, and its definition is enforced by an end-to-end readiness test suite (20 assertions) with adversarial coverage for each hardened rule.

## 1.0.0, 2026-09-08

Pinned dataset: `2026.07.14.01`

### Added

- Documentation restructured into `docs/`: getting started, implementation guide, architecture, certification classes, validation and readiness, continuous integration, automation layers, glossary, frequently asked questions, vision and mission.
- `sdr.py` orchestrator with `build`, `validate`, `scan`, `all`, and `clean` subcommands, so a first run is one command instead of seven.
- `Makefile` with equivalent targets.
- Community health files: contributing guide, security policy, code of conduct, this changelog, issue templates, pull request template.
- Nineteen additional read-only collectors in `automation/collectors/collectors.py` covering the previously described-only indicators (CloudFormation drift, Config conformance packs, WAF, security-group and network-ACL segmentation, CloudTrail and ECR integrity, S3 data protection and retention, SIEM posture, IAM just-in-time and suspicious-activity response wiring, CodePipeline gates, Inspector supply-chain scanning, and Backup restore-testing). Each is read-only (every action enumerated in the `READ_ONLY_ACTIONS` allowlist), emits posture facts rather than statuses, and is offline-testable; the collector test suite grew to 32 tests.
- `automation/config-rules/`: a provider-deployed AWS Config custom-rule scaffold (a shared, parameterized Lambda evidence-existence evaluator, a manifest of eleven rules, a deploy guide, and 6 offline handler tests) for the eleven indicators whose evidence is a document or a reviewed process rather than a live API field. These are provider infrastructure, not repository collectors; a passing result is telemetry, never a status or assessment.
- `automation/collectors/pending-ksi-classification.json`: the machine-readable triage recording which pending indicators became direct read-only collectors versus provider-deployed rules. `build_collector_registry.py` reads it so the collectable-now count regenerates deterministically.
- Five opt-in AI-assist modules in `automation/ai/` (narrative drafter, finding explainer, evidence rollup, over-claim guard, architecture-to-indicator suggester), each with an offline deterministic default backend and an opt-in Amazon Bedrock backend, a forbidden-field boundary guard, and 27 offline boundary tests wired into continuous integration.
- Compliance CAUTION banner at the top of the README: the framework is not a compliance audit bot, no generated output is compliant or guarantees FedRAMP 20x compliance, every generated statement must be independently verified by a qualified human, and AI output is advisory only.
- Continuous-integration wiring for the AI-module boundary suites and the Config custom-rule handler tests.
- Caching of the AWS Automated Security Helper install in the security-scan job, keyed to the pinned version.
- `automation/storage/provision_store.py`: a deploy-time provisioner for the durable metric-history/facts store. It creates an in-boundary S3 bucket in the provider's own account and enables bucket versioning (optionally Object Lock/WORM and a lifecycle retention). Safety-additive and idempotent â€” it never suspends versioning, deletes anything, or moves a status â€” with a DEPLOY guide and 12 offline tests wired into continuous integration.
- `docs/getting-started.md` and `docs/automation.md`: an "Adoption models" note (greenfield vs brownfield, adoption-model-agnostic) and a "Persistence and retention" note recording the 20x retention windows (KSI metric history up to one year per `SDR-CSX-KMT`; 12 months for `SCN-CSO-HIS`; 6 months for `CDS-TRC-ACL`) and clarifying that a seven-year immutable bucket is a provider policy choice, not a 20x requirement.
- Read-only `collect_bucket_versioning` collector (the read-side complement to the store provisioner): reports whether the durable store bucket has versioning enabled, as tamper-resistance/recovery telemetry. `s3:GetBucketVersioning` added to the read-only allowlist; 5 offline tests (collector suite now 37).
- `automation/config-rules/deploy/`: a deterministic generator (`generate_templates.py`) that emits both a CloudFormation template and a CDK-in-Python app for the 11 provider-deployed Config custom rules from the manifest, so the deploy artifacts never drift from it; 7 offline tests. The generated role is read-only on the evidence bucket; a COMPLIANT result stays telemetry, not a determination.
- `automation/metrics/test_metric_history_longitudinal.py`: a 420-day longitudinal test proving the SDR-CSX-KMT rollups (retention cap, up-to-one-year and last-30-day summaries, average passing fraction, same-day idempotency). It documents that the appender retains RETAIN_DAYS+1 points due to the inclusive cutoff (conservative, not data loss).
- `validation/scripts/dataset_diff.py`: an offline tool reporting which rules changed force, applicability, or statement text (plus KSI count/family changes) between two CR26 datasets; wired into the drift-check workflow so a dataset-drift review PR carries a material-changes summary. 7 offline tests.
- `automation/ai/test_bedrock_boundary.py`: boundary tests proving the drafter's forbidden-field guard still holds when a hostile or garbage non-offline (Bedrock-like) backend is behind it, injected through the existing drafter seam without changing production code.
- `examples/sample-offering/`: a fully-worked, fictional sample offering ("Acme Cloud Widgets", Class B) with a builder that swaps the sample inputs in, runs the gate to a green result (0 hard failures), and restores the real inputs. It fills narrative prose only and deliberately does not fabricate statuses, assessments, tests, or evidence, so the readiness scanner honestly reports remaining work.

### Changed

- README rewritten as an entry point rather than a reference manual. Architecture diagrams, the directory map, the validation detail, and the pipeline reference moved into `docs/`.
- Removed an unsupported claim that mapped certification classes A, B, C, and D to the Low, Moderate, and High impact levels. `FRD-CCL` describes them as assurance categories and the dataset does not state that mapping.
- Corrected three indicator names that were paraphrased rather than quoted: `KSI-CMT-LMC` is "Logging Changes", `KSI-IAM-AAM` is "Automating Account Management", and `KSI-IAM-APM` is "Adopting Passwordless Methods". The `INR` family is Incident Response, not Incident Reporting.
- License changed from MIT to all-rights-reserved, associated with Amazon Web Services (AWS) Security Assurance Services (SAS); README badge, README license section, and `CONTRIBUTING.md` updated to match. Ownership and licensing wording is pending confirmation by AWS legal.
- `docs/automation.md`, `docs/vision.md`, `docs/architecture.md`, `docs/faq.md`, `docs/README.md`, `CONTRIBUTING.md`, and `SECURITY.md` updated to reflect the built state: Layer 1 collectors call many read-only actions (not two), and Layer 2 is five built opt-in AI modules (not a single planned drafter).
- Collector coverage: thirty-five of forty-six indicators are now directly collectable read-only (up from sixteen), with the remaining eleven covered by provider-deployed Config custom rules.

### Fixed

- Corrected the described force of `FRC-CSX-VVK` across the README and `docs/getting-started.md`: automated verification of Key Security Indicators is `MAY` at Class A, `SHOULD` (at least one method per indicator) at Class B, and `MUST` at Class C (two) and Class D (four). Earlier wording implied automation was required at Class B. Verified verbatim against the FedRAMP Consolidated Rules for 2026 dataset (`2026.07.14.01`), confirmed current against the upstream `github.com/FedRAMP/rules` repository.

## 0.1.0, 2026-09-05

First working version. Pinned dataset: `2026.07.14.01`.

### Added

- Pinned canonical sources: the CR26 dataset and both official FedRAMP schemas, hash-verified against upstream.
- Seven-step deterministic pipeline: catalogs, notes, profiles, record, Word output, crosswalk, validation.
- Traceability layer: derived rule and indicator catalogs, per-rule notes, family name expansions, and the NIST SP 800-53 Revision 5 to 20x crosswalk.
- Per-class profiles for Classes A, B, and C, the Class C overlay, and the Class D readiness register at 157 rules with a delta against Class C.
- Deliverables for each class: official schema JSON, an isolated provider extensions companion, plain text, and an authoring Word file.
- `validate_sdr.py`, the build gate: eight checks including schema validation, bidirectional coverage, per-class automated-method minimums, secret scanning, and content fidelity re-derived from the dataset through an independent code path.
- `sdrscan.py`, the readiness scanner: 37 checks emitting one finding per rule and per indicator, each citing the governing rule, in five output formats.
- AWS service to indicator map with one verify and one validate method per indicator, matching the `FRC-CSX-VVK` two-method shape.
- Layer 1 facts collector, read-only by construction: two API calls, refuses administrative-looking credentials, writes a git-excluded timestamped facts store.
- GitHub Actions workflows for the validation gate and a daily upstream drift check, with actions pinned to full commit SHAs.
- Deployable AWS CodePipeline reference with the same gates, human approval before publication, and scheduled drift and collection stages.
- Agent guardrails in `.claude/` for automated sessions.

### Fixed

- Every text writer and git blob pinned to LF line endings, so regeneration in continuous integration is byte-stable across platforms.

## Notes on versioning

A change to the pinned dataset is at least a minor version, because generated deliverables change even when no code does. A change that alters what the validator accepts or rejects is a major version, because it can invalidate a record a provider has already built and shipped.
