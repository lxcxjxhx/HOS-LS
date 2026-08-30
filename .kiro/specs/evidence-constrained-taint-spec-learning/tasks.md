# Implementation Plan: Evidence-Constrained Taint Specification Learning

## Overview

Implement ECATSL as a minimal Python orchestration and audit layer under `src/ecatsl/`, reusing existing HOS-LS analysis, SQLite catalog, and benchmark components. The initial scope is Python and CWE-89, CWE-78, and CWE-918.

Extend—not replace—the local SQLite catalog path in `src/nvd/catalog_import.py` and `src/nvd/nvd_query_adapter.py`. Reuse `CatalogImporter`, `NVDQueryAdapter`, existing SQLite storage, `InputTracer`, `SastPrefilter`, `VerificationAdapter`, PureAI, RAG, and `bench/` inputs. Do not add an external catalog store, duplicate catalog pipeline, scanner, or independent CodeQL runner.

Discovery is explicitly framework-agnostic and automated: it may derive and rank non-confirmatory hypotheses from repository code, repository-contained configuration, call graph, supported static evidence, and data-driven semantic templates. It requires no per-route user configuration. Reject only discovery strategies that are simultaneously enumerated per-route rules/patterns, hard-coded rather than evidence/data-driven, non-generalizing, and dependent on users maintaining individual routes. Catalog and discovery assistance never prove controllability or a finding; only qualifying `Path_Evidence` from a supported static adapter can confirm a finding.

## Tasks

- [x] 1. Establish ECATSL foundations, scope, and reuse records
  - [x] 1.1 Create immutable ECATSL artifact, scope, discovery, and reuse models in `src/ecatsl/models.py` and `src/ecatsl/scope.py`
    - Define canonically serialized, content-addressed models for evidence, counterexamples, candidate records/hypotheses, discovery observations/strategies, policies, declarative specifications, validation/path/finding records, catalog/template provenance, scope definitions, reuse inventory, telemetry, datasets, and reports.
    - Encode the Python-only scope with exactly CWE-89, CWE-78, and CWE-918. Return `OUT_OF_SCOPE` before candidate, compilation, adapter, or finding work, and create predecessor-linked scope revisions with incomplete-versioning handling.
    - Make discovery and catalog artifacts explicitly non-confirmatory by model invariant; `PathEvidence` requires supported-adapter identity, entry/source provenance, ordered propagation steps, sink, and sanitizer status.
    - Record a versioned `ReuseInventory` entry before each new ECATSL abstraction, naming the first matching existing HOS-LS component or the documented capability gap and distinct responsibility.
    - _Requirements: 1.1, 1.4, 4.1, 6.1–6.5, 7.1, 7.3, 11.9, 11.12, 11.13_
  - [x] 1.2 Implement an append-only SQLite/Pydantic ECATSL artifact repository in `src/ecatsl/artifact_repository.py`
    - Persist immutable successor versions with predecessor ID, changed-data diff, update cause, canonical hashes, normalized UTC timestamps, provenance, and audit flags; never update historical candidate, policy, scope, reuse, or classification rows.
    - Support atomic candidate/policy lineage writes where possible, candidate-record creation-failure audit events, retained policy outcomes with missing-audit flags, and immutable scope/reuse persistence.
    - Reuse project SQLite support and document the connection boundary so ECATSL metadata can share the existing local catalog database without adding a service or store.
    - _Requirements: 1.1–1.4, 3.7–3.9, 6.4–6.5, 7.1, 7.3_
  - [x] 1.3 Implement deterministic acceptance/validation policy evaluation and candidate lifecycle services in `src/ecatsl/policies.py` and `src/ecatsl/candidate_ledger.py`
    - Implement side-effect-free acceptance and validation decisions, then append results through the artifact repository; map compilation errors, no paths, parameter mismatches, sanitizer evidence, and role/applicability invalidation to configured confidence/state transitions.
    - Require every applicable acceptance-policy condition. Preserve discovery/catalog origin and ranking evidence without treating it as controllability or confirmation evidence.
    - Preserve prior state on policy-application failure while retaining failure provenance where possible; retain validation feedback and counterexamples in immutable successors.
    - _Requirements: 1.5–1.7, 3.1–3.9, 11.9, 11.12–11.13_
  - [x]* 1.4 Write unit and property tests for immutable candidate history and complete provenance in `tests/unit/ecatsl/test_candidate_ledger.py` and `tests/unit/ecatsl/test_policy_provenance_properties.py`
    - **Property 1: Candidate lifecycle is append-only and policy-bounded.** Generate evidence, counterexample, applicability, confidence, and state updates; assert successor lineage, policy-bounded state, and compilation ineligibility.
    - **Property 2: Evidence and policy provenance is complete.** Generate retrieved/transformed evidence and decisions; assert origin, time, identifier/revision, hash, transformations, policy version/outcome, and input identities.
    - Cover candidate-record creation, policy-application, and provenance-write failures with deterministic examples.
    - **Validates: Requirements 1.1–1.7, 3.1–3.9, 5.5**

- [x] 2. Extend the existing local SQLite NVD/CWE catalog path
  - [x] 2.1 Extend `CatalogImporter` and its existing SQLite schema in `src/nvd/catalog_import.py`
    - Add migration-safe ECATSL catalog metadata/derived tables in the same SQLite database: versioned catalog imports, source records, normalized records, canonical/duplicate links, ingestion runs, integrity/completeness reports, taint templates, and template retrieval provenance.
    - Preserve existing `cve`, `cwe`, `cvss`, `cve_cwe`, and catalog-import behavior as the canonical base catalog. Do not create an external store or parallel importer.
    - Import NVD CVE, MITRE CWE, and compatible source records with source origin, source identifier/revision, retrieval timestamp, retrieved-content hash, supplied license/usage metadata, import-tool version, and predecessor linkage.
    - _Requirements: 7.1–7.3, 9.1, 9.3–9.7, 11.1, 11.5_
  - [x] 2.2 Implement deterministic normalization, canonical deduplication, and incremental/idempotent ingestion in `src/nvd/catalog_import.py`
    - Apply versioned normalization profiles so equal source-content identities with the same profile produce equal normalized-content identities and transformation provenance.
    - Canonicalize records sharing `(record_type, canonical_identifier)` or `(record_type, normalized_content_hash)`, retain all duplicate source identities and decisions, and report duplicate counts.
    - Compare each source against its latest completed ingestion run; retain existing canonical records and report zero new canonical records for identical re-ingestion, while selecting only new or changed records for incremental runs.
    - Produce versioned ingestion quality reports with retrieved/imported/normalized/canonical/duplicate/missing-required-field/excluded counts, integrity outcomes, exclusion reasons, source coverage, and catalog-import identities.
    - _Requirements: 9.4–9.7, 11.2–11.7_
  - [x] 2.3 Extend `NVDQueryAdapter` in `src/nvd/nvd_query_adapter.py` with provenance-linked semantic weakness-to-taint-template retrieval
    - Query only in-scope CWE templates from the existing SQLite path and rank them deterministically by semantic weakness-to-template relevance, documented applicability, and available catalog evidence.
    - Persist/query ranking-profile version, query identity, returned template identities, scores, related catalog records, and retrieval provenance; retain the existing CVE/CWE lookup and cache behavior.
    - Return templates exclusively as catalog-assisted ranking inputs for candidate hypotheses. The adapter must expose no API that classifies controllability, emits `PathEvidence`, or confirms findings.
    - _Requirements: 4.3–4.4, 5.1, 6.1–6.3, 11.8–11.9, 11.12–11.13_
  - [x]* 2.4 Write SQLite catalog migration, ingestion, and retrieval tests in `tests/unit/nvd/test_ecatsl_catalog_import.py` and `tests/unit/nvd/test_ecatsl_template_retrieval.py`
    - **Property 16: Catalog normalization, canonicalization, and ingestion are stable.** Generate source identities/content/profile versions; assert deterministic normalized hashes, one canonical record with duplicate linkage, idempotent zero-new-record re-ingestion, and new/changed-only incremental selection.
    - **Property 17: Template retrieval is relevance-ranked and provenance-linked.** Generate in-scope templates/applicability/catalog evidence; assert deterministic relevance ordering and complete score/retrieval/catalog provenance.
    - Cover existing-schema migration compatibility, NVD CVE/MITRE CWE/compatible-source imports, hash mismatch, missing required fields, exclusion reasons, quality-report fields, and preservation of existing adapter query behavior.
    - **Validates: Requirements 9.1, 9.3–9.7, 11.1–11.9**

- [x] 3. Implement framework-agnostic discovery and tooling-first resolution
  - [x] 3.1 Implement generic `DiscoveryAssistance` and `DiscoveryPolicy` in `src/ecatsl/discovery.py`
    - Discover possible endpoints, entrypoints, APIs, sources, sinks, sanitizers, and preconditions from repository code, repository-contained configuration, call graph, supported static-analysis observations, and data-driven semantic templates; retain locations, content identities, producer/version, transformation history, and derivation kind.
    - Implement policy validation that permits generic structural/configuration parsing, call-graph traversal, supported static evidence, and data-driven template strategies without per-route user configuration.
    - Reject a discovery strategy only when it is an enumerated individual-route rule/pattern, hard-coded instead of evidence/data-driven, non-generalizing across supported repository evidence, and requires user maintenance of route entries. Retain rejection reason/provenance and continue with valid generic strategies where possible.
    - Emit only non-confirmatory `CandidateHypothesis` objects and discovery provenance; do not emit confirmation, controllability, or `PathEvidence` decisions.
    - _Requirements: 1.4, 4.2–4.3, 7.1–7.3, 11.9–11.13_
  - [x] 3.2 Implement catalog-assisted hypothesis ranking in `src/ecatsl/discovery.py`
    - Combine generic discovery observations with ranked templates from `NVDQueryAdapter`, producing provenance-linked candidate hypotheses with catalog/discovery labels, ranking profile, inputs, and scores.
    - Preserve applicability and initial-scope checks; catalog/template/discovery signals can rank a hypothesis but cannot satisfy a confirmation condition or bypass acceptance/validation policy.
    - _Requirements: 1.5–1.7, 4.3, 6.1–6.3, 11.8–11.13_
  - [x] 3.3 Implement the recorded-order `ToolingFirstResolver` in `src/ecatsl/tooling_resolver.py`
    - Invoke or record terminal outcomes for every applicable existing SAST/CodeQL, `InputTracer`, RAG, local NVD/CWE SQLite, and PureAI multi-agent capability; capture capability/version, input identity, timing, cost, latency, and failure telemetry.
    - Suppress LLM use when an existing capability resolves role/applicability, including when the resolved tooling record cannot be retained. Permit an LLM attempt only after every applicable capability has a terminal unresolved, inapplicable, unavailable, or failed outcome.
    - Persist LLM model/input/output identities, tokens, cost, latency, outcome/failure data, and linked unresolved tooling records. Failed or assertion-only LLM output remains non-proof and unaccepted without independently sufficient policy evidence.
    - _Requirements: 1.4, 3.8, 5.1–5.7, 7.1–7.2_
  - [x]* 3.4 Write discovery, ranking, and resolver tests in `tests/unit/ecatsl/test_discovery.py` and `tests/unit/ecatsl/test_tooling_resolver_properties.py`
    - **Property 7: Tooling resolution gates LLM fallback.** Generate applicable tool outcomes and retention failures; assert terminal ordering, resolution-based fallback suppression, and `Unknown_API` fallback eligibility only after all terminal unresolved outcomes.
    - **Property 8: LLM output cannot bypass evidence acceptance.** Generate failed/assertion-only LLM outcomes with insufficient independent evidence and assert unaccepted candidate state.
    - **Property 18: Generic discovery is allowed; brittle per-route enumeration is rejected.** Test generic code/config parsing, call-graph traversal, supported static observations, and data-driven templates across multiple repository shapes without a route list; reject only strategies satisfying every brittle per-route criterion.
    - Include fixed cases proving a generic repository configuration parser remains allowed, while a user-maintained literal route table is rejected.
    - **Validates: Requirements 5.1–5.7, 11.10–11.11**
  - [x]* 3.5 Write temporary-repository discovery and local-catalog integration tests in `tests/integration/test_ecatsl_discovery_and_resolution.py`
    - Verify framework-agnostic automated endpoint/entrypoint discovery over repository code, repository configuration, synthetic call graphs, supported static observations, and retrieved templates without per-route user configuration.
    - Verify catalog/discovery output is retained as a ranked hypothesis and remains unconfirmed without a supported static path; verify dispatch/order through stubbed existing SAST/CodeQL, InputTracer, RAG, local SQLite, and PureAI components.
    - **Validates: Requirements 4.2–4.3, 5.1–5.7, 11.8–11.13**

- [x] 4. Build controlled compilation and supported static adapters
  - [x] 4.1 Implement declarative specification validation and compilation in `src/ecatsl/compiler.py`
    - Compile only accepted, non-rejected, adapter-eligible candidate records into declared role, qualified API signature, parameter positions, applicability, and evidence-supported taint semantics.
    - Reject executable logic, callbacks, runtime generation, unknown fields, and unsupported semantics; retain linked `ValidationResult` and `CandidateRecord` artifacts.
    - Exclude unaccepted, rejected, adapter-excluded, invalid, and unsupported candidates without discarding their histories. Discovery/catalog ranking data may remain provenance but cannot be compiled as proof-bearing semantics.
    - _Requirements: 2.1–2.6, 11.9, 11.12–11.13_
  - [x] 4.2 Implement `InputTracerAdapter` and `CodeQLSastAdapter` in `src/ecatsl/static_adapters.py`
    - Define the supported static-adapter protocol and delegate to existing `InputTracer` trace/controllability APIs and `SastPrefilter.cascade`/`codeql_hard_analyze`; do not implement a scanner, query runner, or duplicate analysis pipeline.
    - Normalize compilation errors, unsupported adapters, no-path results, parameter mismatches, sanitizer evidence, and supported static paths. Create `PathEvidence` only when supported static output includes provenance-linked entry/source, ordered propagation, sink, and sanitizer status.
    - Accept discovery hints only as optional analysis prioritization/context. Never convert catalog data, templates, endpoints, entrypoints, LLM output, or discovery observations into static proof.
    - _Requirements: 2.7–2.8, 3.2–3.6, 4.1–4.5, 11.12–11.13_
  - [x] 4.3 Connect static validation feedback to candidate policy updates in `src/ecatsl/static_validation.py`
    - Retain all adapter results and apply recorded validation policy for compilation errors, no paths, parameter mismatches, sanitizer evidence, and role/applicability invalidation.
    - Preserve unsupported-adapter results and candidates without producing a confirmed finding; retain observed versus declared parameter positions and sanitizer/blocking data.
    - _Requirements: 2.3, 2.8, 3.1–3.9, 4.2–4.5_
  - [x]* 4.4 Write compiler and adapter unit/property tests in `tests/unit/ecatsl/test_compiler_properties.py` and `tests/unit/ecatsl/test_static_adapters.py`
    - **Property 3: Compilation is closed over safe eligible declarations.** Assert output is limited to accepted, valid records and allowlisted declarative fields.
    - **Property 4: Invalid declarative inputs are rejected and retained.** Generate executable/unknown/unsupported forms and assert retained rejection results with no emitted specification.
    - Test unsupported adapters, adapter exclusion, validation-feedback transitions, and delegation to fake `InputTracer`/`SastPrefilter` implementations.
    - **Validates: Requirements 2.1–2.8, 3.1–3.9, 4.2–4.5**

- [x] 5. Implement static-path-only confirmation and service orchestration
  - [x] 5.1 Implement `FindingConfirmationService` in `src/ecatsl/confirmation.py`
    - Confirm only when a supported adapter provides complete `PathEvidence` with provenance-linked entry/source, non-empty ordered propagation, sink, and absent/failed sanitizer.
    - Classify missing, incomplete, unsupported, blocking-sanitizer, LLM-only, catalog-only, and discovery-only support as unconfirmed. Attach catalog records only as provenance-linked `ExplanatorySupport`.
    - Retain available candidate/specification/validation/path lineage and missing-metadata flags without rolling back a completed classification.
    - _Requirements: 4.1–4.8, 11.9, 11.12–11.13_
  - [x] 5.2 Implement `ECATSLService`, stage orchestration, and reuse/pipeline governance in `src/ecatsl/service.py` and `src/ecatsl/pipeline.py`
    - Enforce scope gating before discovery, catalog retrieval, candidates, compilation, adapters, or findings. Orchestrate local catalog retrieval, generic discovery/ranking, tooling-first resolution, ledger/policies, compilation, existing adapters, validation feedback, and static-path confirmation in the design order.
    - Deduplicate equal pipeline-stage identities, retaining one stage and its duplicate decision; record consolidation failures while allowing retained stages to execute. Expose reuse-inventory version and configured-adapter/stage/dependency/manual-step complexity counts.
    - Enforce the confirmation boundary at every call boundary: catalog/discovery/LLM outputs can generate or rank hypotheses only, and only supported-adapter `PathEvidence` reaches confirmation.
    - _Requirements: 2.7–2.8, 4.1–4.8, 6.3, 7.1–7.6, 11.8–11.13_
  - [x]* 5.3 Write confirmation and orchestration unit/property tests in `tests/unit/ecatsl/test_confirmation_properties.py`, `tests/unit/ecatsl/test_scope_pipeline_properties.py`, and `tests/integration/test_ecatsl_service.py`
    - **Property 5: Complete supported static paths are necessary and sufficient for confirmation.** Vary static-path completeness, supported status, source provenance, sanitizer state, and catalog/discovery/LLM support; assert confirmation iff qualifying static evidence exists.
    - **Property 6: Finding decisions retain available lineage without rollback.** Generate available lineage and persistence failures; assert unchanged classifications and complete missing-element flags.
    - **Property 9: Scope gating short-circuits downstream work.** Generate out-of-scope requests/revisions and assert no candidate, specification, adapter, or finding artifacts.
    - **Property 10: Reuse and stage consolidation are deterministic.** Generate ordered reusable interfaces and stage identities; assert first-match reuse selection, duplicate consolidation, and complexity reporting.
    - Integration-test a catalog/discovery-assisted hypothesis that remains unconfirmed until a fake supported adapter returns qualifying `PathEvidence`.
    - **Validates: Requirements 4.1–4.8, 6.3–6.5, 7.1–7.6, 11.9, 11.12–11.13**

- [x] 6. Add immutable dataset, evaluation, optimization, and reporting services
  - [x] 6.1 Implement dataset releases in `src/ecatsl/dataset_release.py` using existing `bench/` inputs
    - Create immutable versioned `BenchmarkManifest` and `DataQualityReport` artifacts; verify content hashes, canonicalize duplicate `(content_hash, data_type)` records while retaining identities, record field validity/completeness/exclusions, and enforce deterministic transformations.
    - Model paired vulnerable/fixed-or-clean samples, catalog provenance, and immutable project-time-group train/validation/evaluation splits; create a new manifest identity for tracked artifact/configuration changes.
    - _Requirements: 9.1–9.11_
  - [x] 6.2 Implement evaluation, optimization, and evidence-bounded reporting in `src/ecatsl/evaluation.py` and `src/ecatsl/reporting.py`
    - Calculate verified precision/recall/F1 only from benchmark truth and verified confirmation status, for every non-empty stratum; retain traceable metric inputs and zero-valued cost/failure counters.
    - Record latency, tokens, cost, adapter/stage/dependency/manual-step complexity, audit cost, failures, and rejected candidates. Require exactly one baseline and one changed configuration over the same manifest/strata for optimization experiments.
    - Report improvement only with linked completed experiment evidence and limitations; otherwise report measured differences and missing evidence without a superiority claim. Include reuse inventory and release-selection trade-offs.
    - _Requirements: 7.6, 8.1–8.7, 9.11, 10.1–10.7_
  - [x]* 6.3 Write dataset, evaluation, optimization, and reporting property tests in `tests/unit/ecatsl/test_dataset_properties.py` and `tests/unit/ecatsl/test_evaluation_properties.py`
    - **Property 11: Evaluation and optimization reports are complete and claim-safe.** Generate telemetry/configurations and assert zero-inclusive recording, paired-experiment validity, and guarded claims.
    - **Property 12: Dataset canonicalization and transforms are reproducible.** Generate content/hashes/transform versions and assert integrity outcomes, one canonical record, preserved duplicates, and stable transformed hashes.
    - **Property 13: Benchmark split and version lineage are stable.** Generate groups and tracked changes; assert same-group splits, successor manifests, and retained evaluation lineage.
    - **Property 14: Verified metrics equal the reference calculation.** Generate labels/statuses/strata and compare recorded metrics to a reference implementation.
    - **Property 15: Superiority claims are evidence-gated.** Generate comparison evidence/limitations and assert claims only with linked verified support.
    - **Validates: Requirements 7.6, 8.1–8.7, 9.1–9.11, 10.1–10.7**

- [x] 7. Finalize package wiring and smoke coverage
  - [x] 7.1 Export the ECATSL public surface from `src/ecatsl/__init__.py` and add configuration validation in `src/ecatsl/config.py`
    - Wire the new orchestration layer only to reused HOS-LS components and existing local SQLite catalog configuration; validate serialized scope/policy/schema configuration.
    - Reject only unsupported user-authored brittle per-route strategy configuration as defined by `DiscoveryPolicy`; permit generic framework-agnostic repository/configuration/call-graph/static/template discovery settings without route entries.
    - Keep the Python/CWE-89/CWE-78/CWE-918 scope explicit and ensure catalog/discovery configuration cannot designate a confirmation provider.
    - _Requirements: 2.7, 4.2–4.3, 6.1–6.3, 7.1–7.3, 11.10–11.13_
  - [x]* 7.2 Write the shipped smoke test in `tests/integration/test_ecatsl_smoke.py`
    - Validate existing SQLite schema migration/import/query compatibility, shipped scope, reusable-component availability, and serialized model/policy configuration.
    - Exercise generic discovery from a temporary repository without per-route configuration and a catalog/template-ranked hypothesis that remains unconfirmed.
    - Exercise one positive path through a fake supported static adapter that returns complete provenance-backed `PathEvidence`; verify this is the only route to confirmation.
    - **Property 19: Assisted analysis preserves all proof boundaries.** Assert catalog/discovery-assisted candidate generation retains provenance, scope, reuse, and policy constraints and cannot confirm without the Property 5 path.
    - **Validates: Requirements 2.7, 4.1–4.5, 5.1, 6.1–6.3, 7.1–7.3, 11.8–11.13**

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional test tasks and may be skipped for a faster MVP; an automated task executor must not implement them unless explicitly selected.
- Use the project’s approved Python property-testing library (prefer `hypothesis` if already approved), execute at least 100 generated cases per property, and tag each with `Feature: evidence-constrained-taint-spec-learning, Property N: <title>`.
- Catalog/import work must extend `src/nvd/catalog_import.py`, `src/nvd/nvd_query_adapter.py`, and their existing SQLite database. No external store, analysis-time network dependency, or parallel catalog pipeline is permitted.
- Generic discovery over code, repository configuration, call graph, supported static evidence, and data-driven templates is required and must not require per-route user configuration. The only prohibited route behavior is brittle, enumerated, hard-coded, non-generalizing per-route logic requiring user-maintained route entries.
- Catalog, semantic templates, discovery, endpoint/entrypoint inference, and LLM output generate or rank hypotheses only. Supported static-adapter `PathEvidence` is the exclusive confirmation basis.
- Run non-watch validation after implementation: `poetry run pytest tests -q`, `poetry run flake8 src tests`, and `poetry run mypy src`.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["1.3", "2.2"] },
    { "id": 3, "tasks": ["1.4", "2.3", "2.4"] },
    { "id": 4, "tasks": ["3.1", "3.3"] },
    { "id": 5, "tasks": ["3.2", "3.4"] },
    { "id": 6, "tasks": ["3.5", "4.1"] },
    { "id": 7, "tasks": ["4.2"] },
    { "id": 8, "tasks": ["4.3", "4.4"] },
    { "id": 9, "tasks": ["5.1"] },
    { "id": 10, "tasks": ["5.2", "6.1"] },
    { "id": 11, "tasks": ["5.3", "6.2"] },
    { "id": 12, "tasks": ["6.3", "7.1"] },
    { "id": 13, "tasks": ["7.2"] }
  ]
}
```
