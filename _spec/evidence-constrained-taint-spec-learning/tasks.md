# Implementation Plan: Evidence-Constrained Taint Specification Learning

## Overview

This plan starts from the checked-out workspace, not from prior handoff or PR claims. The only completed ECATSL work is the immutable model/scope foundation in `src/ecatsl/models.py`, `src/ecatsl/scope.py`, and `src/ecatsl/__init__.py`, plus `tests/unit/ecatsl/test_models_and_scope.py`. No production candidate ledger, artifact repository, policy engine, compiler, static adapter, confirmation service, orchestrator, catalog extension, discovery service, dataset release, evaluation, or reporting implementation currently exists.

Implementation remains Python-only for CWE-89, CWE-78, and CWE-918. Extend and reuse existing HOS-LS components first: `src/db/connection.py`, `src/nvd/catalog_import.py`, `src/nvd/etl_batch_import.py`, `src/nvd/nvd_query_adapter.py`, `src/analyzers/input_tracer.py`, `src/analyzers/sast_prefilter.py`, `src/analyzers/verification_adapter.py`, existing PureAI/RAG telemetry, and `bench/` inputs. Catalog, RAG, LLM, endpoint/entrypoint inference, and discovery are non-confirmatory. Only complete `PathEvidence` normalized from a supported static adapter may confirm a finding. Generic repository-driven discovery is allowed; brittle user-maintained route enumeration is forbidden.

## Tasks

- [ ] 1. Lock the verified workspace baseline and reusable contracts
  - [x] 1.1 Retain the existing immutable model, scope, and reuse foundations in `src/ecatsl/models.py`, `src/ecatsl/scope.py`, and `src/ecatsl/__init__.py`
    - Treat these files as data contracts and scope-gate foundations only, not as evidence that the production pipeline exists.
    - Preserve canonical artifact identities, non-confirmatory catalog/discovery models, strict `PathEvidence` shape, Python/CWE scope, and predecessor-linked scope revisions.
    - _Requirements: 1.1, 1.4, 4.1–4.3, 6.1–6.5, 7.1–7.3, 11.9, 11.12–11.13_
  - [x] 1.2 Retain the existing focused foundation tests in `tests/unit/ecatsl/test_models_and_scope.py`
    - Preserve coverage for canonical immutable artifacts, non-confirmatory hypotheses, complete supported path shape, first-match reuse inventory, initial scope, early out-of-scope result, and failed scope versioning.
    - Do not mark any unimplemented ECATSL service or integration behavior complete based on this suite.
    - _Requirements: 4.1–4.3, 6.1–6.5, 7.1–7.3, 11.12–11.13_
  - [x]* 1.3 Add executable baseline compatibility tests in `tests/integration/ecatsl/test_baseline_compatibility.py` and fixtures under `tests/fixtures/ecatsl/baseline/`
    - Characterize the current SQLite catalog schema and public call surfaces of `CatalogImporter`, `BatchImportManager`, `NVDQueryAdapter`, `InputTracer`, `SastPrefilter`, and `VerificationAdapter` before extending them.
    - Assert imports and existing catalog queries remain usable, and record fixture shapes for actual InputTracer and SARIF/CodeQL outputs without treating those raw outputs as `PathEvidence`.
    - Run the existing focused ECATSL suite in non-watch mode to establish the starting result.
    - Execution: Added the baseline fixtures and compatibility test; `.venv\Scripts\python.exe -m pytest tests\unit\ecatsl\test_models_and_scope.py tests\integration\ecatsl\test_baseline_compatibility.py -q` passed with 14 tests. Flake8 was unavailable and remains deferred to later validation.
    - _Requirements: 2.7–2.8, 4.1–4.3, 7.1–7.3, 11.1–11.2_

- [ ] 2. Build migration-safe append-only persistence and recovery first
  - [x] 2.1 Add idempotent ECATSL schema installation in `src/ecatsl/schema.py` and integrate it with the existing SQLite connection boundary in `src/nvd/catalog_import.py`
    - Create append-only artifact, candidate-version, evidence, policy-decision, validation, finding-lineage, scope, reuse-inventory, pipeline-stage, and audit-failure tables without altering or replacing existing `cve`, `cwe`, `cvss`, `cve_cwe`, or catalog-import data.
    - Use schema-version rows and transactional, repeatable migrations that preserve populated databases and fail without leaving a partially advanced schema version.
    - Define uniqueness, predecessor, foreign-key, and content-hash constraints needed to reject mutation or duplicate lineage while allowing safe retry.
    - Execution: Transactional/idempotent append-only ECATSL schema integrated with `CatalogImporter`; all five review findings fixed; focused schema/baseline tests 16 passed, full ECATSL unit/integration suite 24 passed, and `compileall` passed.
    - _Requirements: 1.1–1.4, 3.7–3.9, 4.6–4.7, 6.4–6.5, 7.1–7.5_
  - [x] 2.2 Implement the append-only repository API in `src/ecatsl/artifact_repository.py`
    - Reuse `src/db/connection.py` or the verified SQLite boundary; persist immutable artifacts and successor versions with canonical payload/hash, predecessor, cause, changed fields, normalized UTC time, and provenance.
    - Provide atomic APIs for candidate creation/update, policy outcome plus audit metadata, validation/counterexample retention, classification plus available lineage, scope/reuse revisions, and explicit creation/persistence failure records.
    - Reject in-place updates and stale predecessor writes; make idempotency keys return the previously committed artifact rather than create a second logical version.
    - Execution: Implemented append-only `ArtifactRepository` with dedicated projection APIs, authenticated static-path bindings, preserved policy/classification decisions with missing-metadata flags, a closed model registry, exact idempotency replay, and populated v1→v3 upgrade compatibility. Semantic review APPROVED; focused validation passed 26 tests, the ECATSL suite passed 40 tests, and `compileall` passed.
    - _Requirements: 1.1–1.4, 1.7, 2.6, 3.7–3.9, 4.6–4.7, 6.4–6.5, 7.1, 7.3_
  - [x] 2.3 Add transaction, concurrency, and crash-recovery behavior in `src/ecatsl/artifact_repository.py` and `src/ecatsl/schema.py`
    - Use bounded transactions and compare-and-append semantics so concurrent writers cannot create two successors from the same expected head without an explicit conflict result.
    - Recover safely from interrupted migrations, policy writes, classification metadata writes, lock contention, and process restart; retain successful policy/classification outcomes when later audit metadata fails and flag each missing element.
    - Add retry-safe transaction identifiers and deterministic failure injection hooks used only by tests.
    - Execution: Added bounded `BEGIN IMMEDIATE` acquisition with retry, durable transaction/attempt events, compare-and-append outcomes, test-only failure hooks, BaseException-safe rollback, and conservative crash recovery. Appended immutable schema v6/v7 migrations preserve historical checksums, terminalize v4 legacy starts (including `STARTED → FAILED → STARTED`), enforce attempt ownership, and retain legacy durable idempotency results as logical `COMMITTED`; `UNKNOWN` Windows liveness never interrupts an owner. Built-in atomic migrations produce no no-key retry journal; later extension migrations retain durable journal recovery. Focused pytest: 49 passed; ECATSL unit/integration pytest: 63 passed; `compileall` passed; independent semantic review APPROVED (`semantic-review/2026-08-30-143338-pr-local.md`).
    - _Requirements: 1.2–1.3, 3.7–3.9, 4.6–4.7, 6.5, 7.5_
  - [x]* 2.4 Add persistence, migration, concurrency, and recovery tests in `tests/unit/ecatsl/test_artifact_repository.py` and `tests/integration/ecatsl/test_sqlite_migration_recovery.py`
    - Exercise migration from an existing populated catalog database, repeated migration, rollback on failed DDL, concurrent successor appends, stale-head conflicts, lock retry, interrupted commit/restart, and idempotent replay.
    - Verify candidate-creation failure audit, prior-state restoration after policy failure, preserved classification after metadata failure, immutable history, and no regression to existing NVD/CWE queries.
    - Execution: Added populated SQLite catalog integration coverage using the existing MITRE CWE/NVD fixtures. It verifies repository restart/idempotent replay, failed extension DDL rollback, `BaseException` migration interruption/recovery, repeated installation, and unchanged `NVDQueryAdapter` CWE/CVE results; existing focused repository/schema coverage retains concurrent append, stale-head, lock, audit, immutable-history, and metadata recovery cases. Focused policy/recovery tests: 24 passed; full ECATSL unit/integration pytest: 88 passed; `compileall` passed; independent semantic review APPROVED (`semantic-review/2026-08-30-155948-pr-local.md`).
    - _Requirements: 1.2–1.3, 2.6, 3.7–3.9, 4.6–4.7, 6.5, 7.5, 11.1_

- [ ] 3. Implement deterministic policy, candidate ledger, and declarative compilation
  - [x] 3.1 Implement pure acceptance and validation policy functions in `src/ecatsl/policies.py`
    - Version policy predicates and deterministic mappings for compilation errors, no-path/unreachable results, parameter mismatch, sanitizer evidence, and role/applicability invalidation.
    - Keep catalog/discovery/LLM evidence eligible only for explicitly non-confirmatory origin or ranking conditions; never allow it to satisfy controllability or finding confirmation.
    - Return complete decision payloads containing policy version, outcome, exact evidence/validation identities, confidence/state effect, and audit fields before persistence.
    - Execution: Added pure `evaluate_acceptance` and `apply_validation` functions with deterministic, content-addressed input ordering and complete policy evaluation payloads. Validation maps compilation errors, no-path, parameter mismatch, sanitizer evidence, and role/applicability invalidation to non-promoting lifecycle effects; rejected candidates remain rejected. Independent evidence uses a closed local producer taxonomy; catalog/NVD/RAG/LLM/discovery, known providers/retrievers, and unknown origins are non-independent unless an explicit `origin:<name>` condition selects them. These policy functions never emit controllability or confirmation decisions. Policy tests: 24 passed; full ECATSL unit/integration pytest: 88 passed; `compileall` passed; independent semantic review APPROVED (`semantic-review/2026-08-30-155948-pr-local.md`).
    - _Requirements: 1.5–1.7, 3.1–3.6, 3.8, 5.5, 5.7, 11.12–11.13_
  - [ ] 3.2 Implement candidate lifecycle operations in `src/ecatsl/candidate_ledger.py`
    - Create proposals and immutable successors through `ArtifactRepository`; reject a proposal if initial record creation fails.
    - Recheck accepted records against their recorded acceptance policy immediately before compilation, retain counterexamples, and restore the pre-application state when validation-policy evaluation or persistence fails.
    - Preserve a successful policy outcome with a missing-audit flag when only provenance retention fails.
    - _Requirements: 1.1–1.7, 3.1–3.9_
  - [ ] 3.3 Implement safe input validation and declarative compilation in `src/ecatsl/compiler.py`
    - Accept only declared role, qualified API signature, parameter positions, applicability, and evidence-supported taint semantics from accepted, non-rejected, adapter-eligible candidate versions.
    - Reject executable logic, callbacks, runtime generation, unknown fields, unsupported semantics, and excluded/unsupported candidates while retaining linked validation and candidate records.
    - Record compilation-trigger and completion artifacts; emit no Python callbacks, generated code, scanner logic, or proof claims.
    - _Requirements: 1.6, 2.1–2.6, 2.8, 11.12–11.13_
  - [ ]* 3.4 Write the Property 1 test in `tests/unit/ecatsl/properties/test_property_01_candidate_lifecycle.py`
    - **Property 1: Candidate lifecycle is append-only and policy-bounded.** Generate candidate updates and assert immutable predecessor lineage, retained causes/diffs/counterexamples, policy-prescribed state, and compilation exclusion.
    - **Validates: Requirements 1.1, 1.3, 1.5–1.7, 3.1, 3.3–3.6**
  - [ ]* 3.5 Write the Property 2 test in `tests/unit/ecatsl/properties/test_property_02_policy_provenance.py`
    - **Property 2: Evidence and policy provenance is complete.** Generate evidence transforms and decisions and assert source, time, identity, transformation, policy version/outcome, and exact input identities.
    - **Validates: Requirements 1.4, 3.8, 5.5**
  - [x]* 3.6 Write the Property 3 test in `tests/unit/ecatsl/properties/test_property_03_safe_compilation.py`
    - **Property 3: Compilation is closed over safe eligible declarations.** Generate mixed candidate sets and assert output contains only accepted valid records and allowlisted declarative fields.
    - **Validates: Requirements 2.1, 2.2, 2.4**
    - Execution: Generated mixed accepted/proposed/unaccepted/rejected candidate sets and invalid declaration forms (executable, callback, runtime generation, unknown, unsupported semantics, unqualified signature). Asserted the compiler emits a `ConstrainedDeclarativeSpecification` only for the accepted candidate with evidence-supported semantics, never for non-accepted or invalid records, and that the emitted specification contains only allowlisted declarative fields (role, api_signature, parameter_positions, applicability, taint_semantics) plus immutable artifact metadata — no executable/callback/generated fields. Property test passed (100 examples); full ECATSL suite 85 passed minus legacy `test_properties.py`.
  - [x]* 3.7 Write the Property 4 test in `tests/unit/ecatsl/properties/test_property_04_invalid_input_retention.py`
    - **Property 4: Invalid declarative inputs are rejected and retained.** Generate executable, callback, runtime-generated, unknown, and unsupported forms and assert no specification plus retained linked rejection artifacts.
    - **Validates: Requirements 2.5, 2.6**
    - Execution: Generated all invalid declaration forms (executable logic, callback, runtime generation, unknown field, evidence-unsupported semantics) and asserted `DeclarativeCompiler.compile` rejects them — no specification emitted, each invalid attempt retains linked rejection `ValidationResult` artifacts, and the candidate record/evidence remain retained. Property test passed (100 examples).

- [ ] 4. Normalize real static outputs and enforce the strict PathEvidence gate
  - [x] 4.1 Define supported adapter and normalization contracts in `src/ecatsl/static_adapters.py`
    - Define adapter identity/version/support checks and normalization outcomes for compilation errors, no path, parameter mismatch, sanitizer evidence, incomplete path, unsupported output, and complete static path.
    - Require source provenance, ordered non-empty propagation, sink, sanitizer status, and raw static evidence identity before constructing the existing `PathEvidence` model.
    - Make normalization default to a retained non-confirmatory `ValidationResult`; never infer missing path elements from discovery, catalog, RAG, or LLM data.
    - _Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 4.8_
    - Execution: Replaced the thin placeholder with the normalization contract: `NormalizationOutcome` (COMPILATION_ERROR, NO_PATH, PARAMETER_MISMATCH, SANITIZER_EVIDENCE, INCOMPLETE_PATH, UNSUPPORTED_OUTPUT, COMPLETE_PATH), `NormalizationResult` (always-retained non-confirmatory `ValidationResult` plus optional `PathEvidence`), `build_path_evidence` constructor guard that requires source provenance, ordered non-empty propagation, sink, sanitizer status, and raw static evidence identity and raises instead of synthesizing missing elements, `StaticAdapterContract` protocol with adapter identity/version/support checks, and `supported()` allowlist helper. Smoke-verified complete-path construction, empty-propagation rejection, non-confirmatory default, and confirmatory boundary; full ECATSL suite (excluding legacy `test_properties.py`) 85 passed; `compileall` and module import pass.
  - [x] 4.2 Implement `InputTracerAdapter` in `src/ecatsl/static_adapters.py`
    - Delegate Python/CWE-89, CWE-78, and CWE-918 checks to the actual APIs in `src/analyzers/input_tracer.py`; do not replace or reimplement tracing.
    - Normalize only fixture-compatible complete trace output into `PathEvidence`; map incomplete trace, no path, sanitizer block, mismatched parameter, exception, and unavailable capability to explicit validation/counterexample outcomes.
    - Preserve InputTracer input identity, version/capability identity, timings, raw-output hash, and source-location provenance.
    - Execution: Implemented `InputTracerAdapter` delegating to the actual `InputTracer` controllability APIs. Complete ordered source→propagation→sink trace normalizes into `PathEvidence` via the strict builder guards; empty trace → `NO_PATH`, short path → `INCOMPLETE_PATH`, explicit sanitized/blocked metadata → `SANITIZER_EVIDENCE`, not-exploitable without marker → `NO_PATH`, unavailable capability → `UNSUPPORTED_OUTPUT`, delegated exceptions → retained validation outcome. Preserves adapter/capability identity, raw-output hash, and observed location identities; never infers missing path elements from discovery/catalog/RAG/LLM data. Smoke checks passed; full ECATSL suite exit 0; flake8 clean.
    - _Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 5.1, 7.2_
  - [x] 4.3 Implement `CodeQLSastAdapter` in `src/ecatsl/static_adapters.py`
    - Delegate to `src/analyzers/sast_prefilter.py` and consume real SARIF/CodeQL-oriented fixture shapes; do not add a query runner or scanner.
    - Normalize ordered code-flow locations and sanitizer evidence only when the producer/version is explicitly supported; plain SARIF hits, inferred endpoints, unsupported tool output, or missing source provenance stay unconfirmed.
    - Preserve rule/query identity, run identity, raw-output hash, locations, adapter version, and compatibility failure reason.
    - Execution: Implemented `CodeQLSastAdapter` delegating to the actual `SastPrefilter` CodeQL/SARIF-oriented outputs. Complete ordered code-flow with source/propagation/sink produces `PathEvidence` only when the producer/version is explicitly allowlisted; plain SARIF hits, inferred endpoints, unsupported producer, unavailable capability, or missing provenance stay unconfirmed and retain a non-confirmatory `ValidationResult` carrying rule/query identity, producer/version, raw-output hash, locations, adapter version, and compatibility failure reason. Smoke checks passed; full ECATSL suite exit 0; flake8 clean.
    - _Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 5.1, 7.2_
  - [ ] 4.4 Connect normalized static feedback to candidate updates in `src/ecatsl/static_validation.py`
    - Persist every adapter result and apply the recorded validation policy for compilation errors, no paths, parameter mismatches, sanitizer evidence, and role/applicability invalidation.
    - Retain observed and declared parameter positions, sanitizer/blocking data, unsupported-adapter outcomes, candidate lineage, and recovery flags without manufacturing a path.
    - _Requirements: 2.3, 2.8, 3.1–3.9_
  - [x] 4.5 Implement `FindingConfirmationService` in `src/ecatsl/confirmation.py`
    - Confirm if and only if a supported adapter produced complete provenance-backed `PathEvidence` with absent or failed sanitizer; blocking sanitizer or any missing/incompatible element is unconfirmed.
    - Attach CWE/NVD records only as `ExplanatorySupport`; retain all available candidate, specification, validation, and path identities.
    - Preserve the classification and enumerate missing metadata when lineage persistence partially fails.
    - Execution: Implemented `FindingConfirmationService` with strict pure predicate (`supported_adapter` + source provenance identity + non-empty propagation + sink + sanitizer status in {ABSENT, FAILED}); blocking sanitizer or any missing/incompatible path element stays UNCONFIRMED. CWE/NVD records attach only as `ExplanatorySupport` (`explanatory_support_ids` with backward-compatible `explanatory_ids` alias, mutually exclusive), all available candidate/specification/validation/path identities are retained, and repository-backed persistence returns `ClassificationPersistenceResult` that preserves the classification and enumerates exact `missing_metadata` plus one `AuditFailureRecord` per element when lineage persistence partially fails. Added 12 test cases in `tests/unit/ecatsl/test_confirmation.py` covering pure-decision confirm/blocking-sanitizer/failed-sanitizer/no-path/explanatory-only/alias-conflict/missing-metadata-dedup and repository persistence confirm, missing-lineage flags, cross-candidate lineage rejection, append-only idempotency, and unconfirmed-without-path. `python -m pytest tests/unit/ecatsl/test_confirmation.py -q` passed 12/12; legacy `test_properties.py` failures are pre-existing and unrelated to 4.5.
    - _Requirements: 4.1–4.8, 11.12–11.13_
  - [x]* 4.6 Add fixture-based adapter compatibility tests in `tests/unit/ecatsl/test_static_adapters.py` with fixtures under `tests/fixtures/ecatsl/static/`
    - Cover actual InputTracer return shapes and supported/unsupported SARIF/CodeQL-oriented code-flow shapes, including complete path, plain hit, missing provenance, empty propagation, sanitizer block/failure, malformed output, and adapter exception.
    - Assert adapters delegate to `InputTracer`/`SastPrefilter`, retain raw identity and failures, and never upgrade catalog/discovery/LLM hints into path elements.
    - Execution: Added 12 JSON fixtures (`input_tracer_*.json`, `codeql_*.json`, `adapter_exception.json`) and 13 pytest cases in `test_static_adapters.py` covering complete-path confirmation, NO_PATH, INCOMPLETE_PATH, SANITIZER_EVIDENCE, plain-hit/missing-provenance/empty-propagation/malformed unconfirmed outcomes, adapter-exception failure retention, delegation binding, and hint-no-upgrade. Also fixed `CodeQLSastAdapter._flow_from_hit` to require source + intermediate propagation + sink (two-node flows stay unconfirmed) and added `_hit_has_blocking_sanitizer` mapping blocking/failed sanitizer evidence to SANITIZER_EVIDENCE. 13/13 tests pass; full ECATSL suite exit 0; flake8 clean on the three touched files.
    - Cover actual InputTracer return shapes and supported/unsupported SARIF/CodeQL code-flow shapes, including complete path, plain hit, missing provenance, empty propagation, sanitizer block/failure, malformed output, and adapter exception.
    - Assert adapters delegate to `InputTracer`/`SastPrefilter`, retain raw identity and failures, and never upgrade catalog/discovery/LLM hints into path elements.
    - _Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 7.2, 11.12–11.13_
  - [x]* 4.7 Write the Property 5 test in `tests/unit/ecatsl/properties/test_property_05_static_path_confirmation.py`
    - **Property 5: Complete supported static paths are necessary and sufficient for confirmation.** Generate support sets, path completeness, producer support, source provenance, and sanitizer states; assert confirmation exactly at the static proof boundary.
    - **Validates: Requirements 4.1–4.3, 4.5, 4.8, 11.12**
    - Execution: Added `tests/unit/ecatsl/properties/test_property_05_static_path_confirmation.py` with three tests. Generated sweeps over path presence, propagation presence, and sanitizer state (ABSENT/FAILED/BLOCKING) assert `FindingConfirmationService.classify` confirms exactly when the path is complete and supported with sanitizer ABSENT or FAILED, and stays unconfirmed for every missing/incompatible combination; hint-only (no path) never confirms; and model construction rejects unsupported producers, empty source provenance, and empty propagation, proving missing path elements cannot be synthesized. Property suite: 10 passed (100 examples each).
  - [x]* 4.8 Write the Property 6 test in `tests/unit/ecatsl/properties/test_property_06_finding_lineage.py`
    - **Property 6: Finding decisions retain available lineage without rollback.** Generate available lineage and metadata-write failures and assert unchanged classification plus exact missing-element flags.
    - **Validates: Requirements 4.6, 4.7**
    - Execution: Added `tests/unit/ecatsl/properties/test_property_06_finding_lineage.py` with three tests. Generated lineage-availability sweeps assert pure classification depends only on the static path; persisted complete lineage (candidate→specification→validation→adapter run→path) is retained with zero failures; and injected `OptionalMetadataPersistenceError` via `ArtifactRepository.for_testing` preserves the CONFIRMED classification while enumerating exact `missing_metadata` flags with one failure record per missing element. Property suite: 10 passed (100 examples each).

- [ ] 5. Wire the ECATSL service with tooling order and failure isolation
  - [x] 5.1 Implement the tooling-first resolver in `src/ecatsl/tooling_resolver.py`
    - Adapt existing SAST/CodeQL, InputTracer, PureAI multi-agent, RAG, and local NVD/CWE capabilities behind terminal `RESOLVED`, `UNRESOLVED`, `INAPPLICABLE`, `UNAVAILABLE`, or `FAILED` records with validated identity, timing, cost, and failure telemetry.
    - Suppress LLM fallback after any existing-tool role/applicability resolution, including tooling-record retention failure; permit fallback only after every applicable capability has a terminal unresolved outcome.
    - Persist complete LLM attempt telemetry and keep failed/assertion-only output unaccepted without independent policy-satisfying evidence.
    - _Requirements: 3.8, 5.1–5.7, 7.1–7.3_
    - Execution: Implemented `ToolingFirstResolver` in `src/ecatsl/tooling_resolver.py` replacing the thin placeholder. It runs capabilities in declared order, converts each to a validated `ToolingResolutionRecord` (terminal-outcome enforcement, latency/cost/failure telemetry), stops early on the first `RESOLVED` capability, suppresses LLM fallback in that case, and permits the LLM only when every applicable capability ended terminal-unresolved (`unknown_api=True`). Capability exceptions are retained as `FAILED` telemetry records rather than fatal; all records and any LLM attempt are persisted through `ArtifactRepository.persist_artifact` when a repository is configured. Added 4 tests in `tests/unit/ecatsl/test_tooling_resolver.py` covering terminal-outcome gating, early-stop suppression, all-terminal-unresolved fallback with persisted telemetry, and exception→FAILED retention. Focused pytest: 4 passed; compileall passed.
  - [x] 5.2 Implement stage identity, consolidation, and execution isolation in `src/ecatsl/pipeline.py`
    - Deduplicate equal pipeline-stage identities deterministically and record the decision; if consolidation persistence fails, retain and execute both stages with an audit failure.
    - Define required versus optional stage failures, per-stage artifacts, timeout/cancellation boundaries, and continuation rules so catalog, discovery, RAG, LLM, or one adapter failure cannot bypass scope, policy, compilation, or confirmation gates.
    - Calculate configured adapter, stage, external dependency, and manual-step counts from the actual assembled pipeline.
    - _Requirements: 7.1–7.6, 8.1_
    - Execution: Implemented the full Task 5.2 surface in `src/ecatsl/pipeline.py`. `stage_identity` deterministically binds input identities/types, transformation purpose, and output identities/types; `consolidate_stages` keeps the first occurrence canonical and lists later equal identities as duplicates. `persist_consolidation` persists canonical stages, records each duplicate decision as a `pipeline_stage_consolidation` `AuditFailureRecord` linked to the canonical stage, and on consolidation-persistence failure retains and executes both matching stages while auditing the consolidation failure. `ArtifactRepository.persist_pipeline_stage`/`find_canonical_pipeline_stage` register `PipelineStage` in the model registry with a dedicated idempotent persistence API (canonical NULL binding, duplicate binding validated against the canonical stage and consolidation audit record; schema trigger enforcement) plus a test-only consolidation-decision failure hook. `Pipeline.run` isolates required vs optional failures (optional catalog/discovery/RAG/LLM/adapter failures continue; required gate failures stop downstream), enforces per-stage timeouts and cancellation boundaries, and passes per-stage artifacts downstream. `compute_complexity` counts adapters, consolidated stages, external dependencies, and manual steps from the actual assembled pipeline. Added 10 tests in `tests/unit/ecatsl/test_pipeline.py`. Focused pytest: 10 passed; full ECATSL unit/integration suite (excluding legacy `test_properties.py`): 144 passed; `compileall` and flake8 fatal checks pass.
  - [x] 5.3 Implement the fully wired core orchestrator in `src/ecatsl/service.py`
    - Implement `ECATSLService.analyze` with scope short-circuit, discovery/catalog provider ports, tooling-first resolution, candidate ledger, policy checks, compiler, supported static adapters, validation feedback, confirmation, and artifact retention in design order.
    - Inject concrete existing HOS-LS adapters and repositories; do not instantiate a second scanner, database, catalog pipeline, or analysis-time catalog network client.
    - Isolate provider/adapter failures, preserve partial audit artifacts, never call downstream candidate/spec/adapter/finding work after out-of-scope detection, and allow confirmation only through `FindingConfirmationService`.
    - _Requirements: 1.2, 2.1–2.8, 3.7–3.9, 4.1–4.8, 5.1–5.7, 6.3, 7.1–7.6, 11.12–11.13_
    - Execution: Implemented `ECATSLService` in `src/ecatsl/service.py` with `AnalysisRequest`/`AnalysisResult`/`ValidationOutcome`/`CompiledCandidate` contracts. `analyze` runs the design-order pipeline: versioned scope gate with immediate `OUT_OF_SCOPE` short-circuit (no downstream candidate/spec/adapter/finding work), non-confirmatory discovery/catalog/ranking provider ports with isolated audited failures, tooling-first API resolution through `ToolingFirstResolver`, `CandidateLedger` proposal + acceptance-policy lifecycle with compilation-boundary recheck, `DeclarativeCompiler` compilation (adapter eligibility/support flags; unsupported adapters retained with `UNSUPPORTED_ADAPTER`), supported static adapters executed and normalized with `StaticValidationService` feedback and `StaticAdapterRun`/`PathEvidence` retention, and confirmation exclusively through `FindingConfirmationService` (every candidate classified; only complete supported static paths confirm). Provider/adapter exceptions become `AuditFailureRecord` entries without bypassing gates; each stage persists a consolidated `PipelineStage` artifact; `OperationalComplexity` is derived from the assembled pipeline. Added 8 tests in `tests/unit/ecatsl/test_service.py`. Focused pytest: 8 passed; full ECATSL unit/integration suite (excluding legacy `test_properties.py`): 152 passed; `compileall` and flake8 fatal checks pass.
  - [x]* 5.4 Add orchestration and failure-isolation integration tests in `tests/integration/ecatsl/test_service_orchestration.py`
    - Assert stage order and retained artifacts for happy path, out-of-scope request, unsupported adapter, catalog outage, discovery failure, RAG/LLM failure, adapter exception, policy persistence failure, metadata failure, and restart/replay.
    - Verify catalog/discovery/LLM-only support always ends unconfirmed and one complete fake supported static path is the only positive confirmation case.
    - Execution: Added 11 integration tests in `tests/integration/ecatsl/test_service_orchestration.py` over a real on-disk `ArtifactRepository`: happy path (exact 7-stage order, every stage output reloadable, confirmed only via `ecatsl_path_evidence`), restart/replay (repository reopened, clock frozen across `service`/`candidate_ledger`/`compiler`/`confirmation`, replay reproduces identical stage/candidate/specification/classification artifact ids and survives reopen), out-of-scope short-circuit (scope artifact retained, zero candidate rows), unsupported adapter (limitation, no specification/path), catalog outage (`template_retrieval` audited, confirmation gates hold), discovery failure (`discovery` audited, downstream empty, stage order intact), LLM failure (`tooling_resolution` audited, terminal tooling telemetry retained), adapter exception (`static_adapter` audited, candidate/spec retained, unconfirmed), acceptance-policy optional-metadata failure via `policy.optional_audit_metadata` hook (outcome preserved, `missing_audit_elements` flagged, `policy_audit` rows retained), classification metadata failure via `classification.optional_audit_metadata` hook (CONFIRMED preserved with exact `missing_metadata` flag), and an assistance-only pair proving catalog/discovery/LLM support never confirms without a complete supported static path. Fixed one production defect surfaced by the suite: `ECATSLService._resolve_apis` treated the empty tuple returned by `_guarded` on resolver failure as a valid bundle (`bundle is not None` → `bundle`), which crashed orchestration with `AttributeError` instead of isolating the failure. Focused pytest: 11 passed; full ECATSL unit/integration suite (excluding legacy `test_properties.py`): 163 passed; flake8 clean on touched files.
    - _Requirements: 1.2, 2.7–2.8, 3.7–3.9, 4.1–4.8, 5.1–5.7, 6.3, 7.4–7.5, 11.12–11.13_
  - [x]* 5.5 Write the Property 7 test in `tests/unit/ecatsl/properties/test_property_07_tooling_gate.py`
    - **Property 7: Tooling resolution gates LLM fallback.** Generate applicable tool sets, terminal outcomes, and retention failures; assert ordering, suppression, and `Unknown_API` eligibility.
    - **Validates: Requirements 5.1–5.4**
    - Execution: Added `tests/unit/ecatsl/properties/test_property_07_tooling_gate.py` with 4 tests. Generated outcome combinations assert ordered execution up to the first `RESOLVED`, LLM suppression whenever any capability resolves, fallback eligibility only when all capabilities are terminal-unresolved, and `FAILED`/exception outcomes retained as terminal telemetry. Focused pytest: 4 passed; full property suite 33 passed.
  - [x]* 5.6 Write the Property 8 test in `tests/unit/ecatsl/properties/test_property_08_llm_noninterference.py`
    - **Property 8: LLM output cannot bypass evidence acceptance.** Generate failed/assertion-only results and insufficient independent evidence and assert the candidate remains unaccepted.
    - **Validates: Requirements 5.7**
    - Execution: Added `tests/unit/ecatsl/properties/test_property_08_llm_noninterference.py` with 3 tests. Generated LLM-outcome × evidence-availability sweeps assert LLM-origin evidence never satisfies the independent-evidence acceptance condition, LLM assertion content/confidence never upgrades acceptance, and failed LLM telemetry never becomes a static path. Focused pytest: 3 passed; full property suite 33 passed.
  - [ ]* 5.7 Write the Property 9 test in `tests/unit/ecatsl/properties/test_property_09_scope_short_circuit.py`
    - **Property 9: Scope gating short-circuits downstream work.** Generate unsupported languages/CWEs and scope revisions and assert no candidate, specification, adapter, or finding artifacts.
    - **Validates: Requirements 6.3, 6.4**
  - [ ]* 5.8 Write the Property 10 test in `tests/unit/ecatsl/properties/test_property_10_reuse_and_stages.py`
    - **Property 10: Reuse and stage consolidation are deterministic.** Generate ordered reuse candidates and stage identities and assert first-match selection, duplicate consolidation, and recorded failure behavior.
    - **Validates: Requirements 7.2, 7.4**

- [ ] 6. Extend catalog ingestion and add scalable deterministic discovery
  - [ ] 6.1 Extend the existing catalog migration/import path in `src/nvd/catalog_import.py`
    - Add versioned catalog-import, source-record, normalized-record, canonical/duplicate, ingestion-run, quality-report, taint-template, and retrieval-provenance tables through the migration framework from Task 2.
    - Delegate NVD CVE/MITRE CWE parsing and base upserts to `CatalogImporter`/`BatchImportManager`; preserve existing canonical catalog tables and record source origin/revision, retrieval hash/time, license metadata, tool version, and predecessor.
    - Stream or batch records rather than loading a realistic catalog release fully into memory.
    - _Requirements: 7.1–7.3, 9.1, 9.3–9.7, 11.1, 11.5_
  - [ ] 6.2 Implement deterministic normalization, deduplication, incremental import, and data-quality telemetry in `src/nvd/catalog_import.py`
    - Produce stable normalized identities from source content identity plus normalization-profile version; canonicalize by identifier/type or normalized hash/type while retaining all duplicate source identities and decisions.
    - Compare against the latest completed run, process only new/changed records, report zero new canonical records on identical replay, and commit bounded batches with resumable checkpoints.
    - Emit retrieved/imported/normalized/canonical/new/duplicate/missing/failed-integrity/excluded counts, reasons, coverage, import identities, latency, and peak batch size for each run.
    - _Requirements: 9.4–9.7, 11.2–11.7_
  - [ ] 6.3 Add deterministic semantic template retrieval in `src/nvd/nvd_query_adapter.py`
    - Retrieve only in-scope templates and rank by a versioned deterministic combination of semantic weakness relevance, applicability match, and available catalog evidence with stable tie-breaking.
    - Persist query identity, ranking profile, inputs, template/catalog identities, component scores, final scores, and retrieval provenance while preserving current CVE/CWE queries and cache behavior.
    - Return non-confirmatory ranking input only; expose no confirmation or controllability API.
    - _Requirements: 4.3–4.4, 6.1–6.3, 11.8–11.9, 11.12–11.13_
  - [ ] 6.4 Implement generic discovery and discovery-policy validation in `src/ecatsl/discovery.py`
    - Reuse `ASTAnalyzer`, `ConfigScanner`, available call-graph inputs, and normalized static observations to discover repository-derived endpoints, entrypoints, APIs, roles, sanitizers, and preconditions without user-authored route lists.
    - Permit generic structural/configuration/call-graph/static/template strategies. Reject only strategies that are simultaneously enumerated per-route, hard-coded, non-generalizing, and user-maintained.
    - Emit provenance-linked non-confirmatory observations/hypotheses and data-quality telemetry for parsed/skipped/invalid files and discovery failures.
    - _Requirements: 1.4, 4.2–4.3, 7.1–7.3, 11.9–11.13_
  - [ ] 6.5 Implement deterministic catalog-assisted hypothesis ranking and connect concrete providers in `src/ecatsl/discovery.py` and `src/ecatsl/service.py`
    - Combine observations with ranked templates using versioned scores and stable tie-breaking, retaining all discovery/catalog inputs and applicability/scope decisions.
    - Wire the local SQLite catalog and generic discovery providers into the service while preserving failure isolation and the rule that hypotheses cannot become proof or bypass acceptance policy.
    - _Requirements: 1.5–1.7, 4.3, 6.1–6.3, 11.8–11.13_
  - [ ]* 6.6 Add realistic-scale catalog and discovery integration tests in `tests/integration/ecatsl/test_catalog_discovery_scale.py` and fixtures under `tests/fixtures/ecatsl/catalog/`
    - Exercise populated-schema migration, repeated and changed-only imports, duplicate canonicalization, interrupted batch resume, stable ranking, cache compatibility, bounded batch behavior, and complete quality telemetry over a generated multi-thousand-record fixture.
    - Exercise generic code/config/call-graph/static discovery across multiple repository shapes without route configuration; assert literal user-maintained route enumeration is rejected and every resulting hypothesis stays unconfirmed without a static path.
    - _Requirements: 9.3–9.7, 11.1–11.13_
  - [ ]* 6.7 Write the Property 16 test in `tests/unit/ecatsl/properties/test_property_16_catalog_ingestion.py`
    - **Property 16: Catalog normalization, canonicalization, and ingestion are stable.** Generate source identities/content/profile/tool versions and assert stable hashes, one canonical record, retained duplicates, zero-new replay, and new/changed-only selection.
    - **Validates: Requirements 11.2–11.4, 11.6–11.7**
  - [ ]* 6.8 Write the Property 17 test in `tests/unit/ecatsl/properties/test_property_17_template_ranking.py`
    - **Property 17: Template retrieval is relevance-ranked and provenance-linked.** Generate templates, applicability, catalog evidence, and ties and assert deterministic ordering and complete scoring/retrieval provenance.
    - **Validates: Requirements 11.8–11.9**
  - [ ]* 6.9 Write the Property 18 test in `tests/unit/ecatsl/properties/test_property_18_discovery_policy.py`
    - **Property 18: Generic discovery is allowed; brittle per-route enumeration is rejected.** Generate strategy traits and repository evidence and assert rejection exactly when all prohibited route-maintenance traits hold.
    - **Validates: Requirements 11.10–11.11**
  - [ ]* 6.10 Write the Property 19 test in `tests/unit/ecatsl/properties/test_property_19_assistance_noninterference.py`
    - **Property 19: Assisted analysis preserves all proof boundaries.** Generate catalog/discovery-assisted hypotheses and assert provenance, scope, reuse, and policy constraints plus no confirmation without Property 5 evidence.
    - **Validates: Requirements 11.13**

- [ ] 7. Prevent benchmark leakage and implement verified evaluation/reporting
  - [ ] 7.1 Implement immutable dataset releases and leakage-safe splits in `src/ecatsl/dataset_release.py` using existing `bench/` inputs
    - Build vulnerable/fixed-or-clean paired samples with source metadata, collection time, hashes, pair links, catalog provenance, and project-time groups.
    - Verify hashes, canonicalize equal hash/type records while retaining duplicate identities, apply deterministic transforms, and emit completeness/validity/integrity/exclusion quality data.
    - Assign project-time groups atomically to train/validation/evaluation so a project/time group and each paired vulnerable/fixed-or-clean relationship cannot leak across splits; create a new manifest version for every tracked input/configuration change.
    - _Requirements: 9.1–9.11_
  - [ ] 7.2 Implement vulnerable/fixed/clean evaluation in `src/ecatsl/evaluation.py`
    - Calculate confusion matrices and verified precision/recall/F1 only from benchmark truth plus verified finding classifications, globally and for every non-empty CWE/language/framework/project/sample-class stratum.
    - Retain manifest/quality versions, sample hashes, label and classification identities, baseline configuration, audit cost, latency, token/cost data, failures, rejected candidates, and zero values.
    - Validate paired baseline/change experiments against the same manifest, strata, sample hashes, and environment before calculating differences.
    - _Requirements: 7.6, 8.1–8.3, 9.11, 10.1–10.4, 10.6_
  - [ ] 7.3 Implement evidence-bounded cost and comparison reporting in `src/ecatsl/reporting.py`
    - Report verified metrics, analysis and audit cost, LLM tokens/money, tooling and LLM failures, rejected candidates, reuse inventory, and operational complexity for the evaluation and every non-empty stratum.
    - Emit optimization or superiority claims only when linked completed evidence supports them and limitations are stated; otherwise report measured results and explicit missing/insufficient evidence without superiority language.
    - Record release-configuration trade-offs against completed optimization experiments.
    - _Requirements: 7.6, 8.1–8.7, 10.1–10.7_
  - [ ]* 7.4 Write the Property 11 test in `tests/unit/ecatsl/properties/test_property_11_claim_safe_optimization.py`
    - **Property 11: Evaluation and optimization reports are complete and claim-safe.** Generate telemetry/configurations and assert zero-inclusive metrics, paired-experiment validity, and evidence-gated improvement claims.
    - **Validates: Requirements 8.1–8.6**
  - [ ]* 7.5 Write the Property 12 test in `tests/unit/ecatsl/properties/test_property_12_dataset_canonicalization.py`
    - **Property 12: Dataset canonicalization and transforms are reproducible.** Generate records, supplied hashes, duplicates, and transform versions and assert integrity outcomes, one canonical record, retained identities, and stable output hashes.
    - **Validates: Requirements 9.4–9.6**
  - [ ]* 7.6 Write the Property 13 test in `tests/unit/ecatsl/properties/test_property_13_split_lineage.py`
    - **Property 13: Benchmark split and version lineage are stable.** Generate project-time groups, pairs, and tracked changes and assert no group/pair leakage, immutable successor manifests, and retained evaluation lineage.
    - **Validates: Requirements 9.8–9.11**
  - [ ]* 7.7 Write the Property 14 test in `tests/unit/ecatsl/properties/test_property_14_verified_metrics.py`
    - **Property 14: Verified metrics equal the reference calculation.** Generate vulnerable/fixed/clean labels, verified statuses, and strata and compare every non-empty result to a reference confusion matrix.
    - **Validates: Requirements 10.1–10.4**
  - [ ]* 7.8 Write the Property 15 test in `tests/unit/ecatsl/properties/test_property_15_superiority_gate.py`
    - **Property 15: Superiority claims are evidence-gated.** Generate comparison evidence and limitations and assert claims only with linked verified support and stated limitations.
    - **Validates: Requirements 10.5–10.7**
  - [ ]* 7.9 Add paired-evaluation integration tests in `tests/integration/ecatsl/test_verified_evaluation.py`
    - Evaluate vulnerable/fixed/clean fixtures with confirmed, unconfirmed, false-positive, false-negative, empty-stratum, zero-cost, and partial-failure cases.
    - Assert split leakage prevention, per-stratum traceability, cost/complexity completeness, baseline identity, and absence of unsupported superiority claims.
    - _Requirements: 8.1–8.7, 9.1–9.11, 10.1–10.7_

- [ ] 8. Complete package wiring and executable validation
  - [ ] 8.1 Export and validate the production surface in `src/ecatsl/__init__.py` and `src/ecatsl/config.py`
    - Export `ECATSLService` and supported configuration/repository/adapter contracts; validate scope, policies, SQLite configuration, adapter support declarations, and deterministic ranking profiles.
    - Reject user-authored brittle route enumeration while allowing generic repository/config/call-graph/static/template discovery; prevent catalog/discovery/LLM providers from being configured as confirmation providers.
    - _Requirements: 2.7–2.8, 4.1–4.3, 6.1–6.3, 7.1–7.3, 11.10–11.13_
  - [ ]* 8.2 Add the end-to-end automated smoke test in `tests/integration/ecatsl/test_smoke.py`
    - Start from an existing populated SQLite catalog fixture, run idempotent migration, generic discovery, catalog ranking, policy/ledger/compiler, fixture-backed static adapter normalization, confirmation, and verified reporting through `ECATSLService`.
    - Assert discovery/catalog-only and unsupported/static-incomplete cases remain unconfirmed, while exactly one complete supported static path confirms; verify all lineage and telemetry survives restart/replay.
    - _Requirements: 1.1–1.7, 2.1–2.8, 3.1–3.9, 4.1–4.8, 5.1–5.7, 6.1–6.3, 7.1–7.6, 8.1, 9.11, 10.1, 11.8–11.13_
  - [ ]* 8.3 Run non-watch targeted and full validation for the implemented surface
    - Run `poetry run pytest tests/unit/ecatsl tests/integration/ecatsl -q`, then `poetry run pytest tests -q`, `poetry run flake8 src tests`, and `poetry run mypy src` without watch mode.
    - Fix implementation/test failures before completion and retain the exact commands and results in the task execution record; do not start a development server or interactive watcher.
    - _Requirements: 1.1–11.13_

- [ ] 9. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Checked tasks reflect only files and tests present in this workspace. No prior PR or handoff statement changes completion status without matching checked-out code.
- Tasks marked with `*` are optional automated test/validation tasks under the spec workflow and may be selected independently; core implementation tasks are never optional.
- Each correctness property has its own test task. Use the project-approved Python property-testing library with at least 100 generated cases and tag each test `Feature: evidence-constrained-taint-spec-learning, Property N: <title>`.
- Persistence and catalog work must share the existing SQLite path and preserve existing NVD/CWE behavior. No external catalog store, duplicate scanner/importer, analysis-time catalog download, or independent CodeQL runner is permitted.
- Generic discovery from repository code, repository-contained configuration, call graph, supported static observations, and data-driven templates is required. Only brittle enumerated hard-coded route logic requiring user maintenance is prohibited.
- Catalog, RAG, LLM, templates, discovery, and inferred endpoints/entrypoints are hypotheses or explanatory support only. Complete `PathEvidence` from a supported static adapter is the exclusive confirmation basis.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["3.2"] },
    { "id": 1, "tasks": ["3.3", "3.4", "3.5"] },
    { "id": 2, "tasks": ["3.6", "3.7", "4.1"] },
    { "id": 3, "tasks": ["4.2"] },
    { "id": 4, "tasks": ["4.3"] },
    { "id": 5, "tasks": ["4.4", "4.6"] },
    { "id": 6, "tasks": ["4.5"] },
    { "id": 7, "tasks": ["4.7", "4.8", "5.1"] },
    { "id": 8, "tasks": ["5.2", "5.5", "5.6"] },
    { "id": 9, "tasks": ["5.3", "5.8"] },
    { "id": 10, "tasks": ["5.4", "5.7"] },
    { "id": 11, "tasks": ["6.1"] },
    { "id": 12, "tasks": ["6.2"] },
    { "id": 13, "tasks": ["6.3"] },
    { "id": 14, "tasks": ["6.4", "6.7"] },
    { "id": 15, "tasks": ["6.5", "6.8", "6.9"] },
    { "id": 16, "tasks": ["6.6", "6.10"] },
    { "id": 17, "tasks": ["7.1"] },
    { "id": 18, "tasks": ["7.2"] },
    { "id": 19, "tasks": ["7.3", "7.5", "7.6"] },
    { "id": 20, "tasks": ["7.4", "7.7", "7.8", "7.9"] },
    { "id": 21, "tasks": ["8.1"] },
    { "id": 22, "tasks": ["8.2"] },
    { "id": 23, "tasks": ["8.3"] }
  ]
}
```
