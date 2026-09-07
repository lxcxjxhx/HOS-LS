# Requirements Document

## Introduction

Evidence-Constrained Adaptive Taint Specification Learning (ECATSL) is a HOS-LS feature that learns narrowly scoped declarative taint-analysis specifications from repository evidence and versioned local vulnerability knowledge. ECATSL validates candidate specifications through existing static-analysis capabilities and confirms findings only when static Path_Evidence from a supported Static_Analysis_Adapter supports the reported source-to-sink flow. LLM assertions, catalog text, inferred endpoint or entrypoint information, and unsupported adapter outputs are not vulnerability proof. ECATSL may use generalizable automated discovery over repository, configuration, call-graph, and static evidence, plus imported NVD CVE, MITRE CWE, and compatible catalog knowledge, to assist candidate generation and hypothesis ranking. The initial release supports exactly one implementation language and two or three CWE mappings for that language. ECATSL reports measured results without asserting superiority unless a comparison is supported by recorded verified evidence.

## Glossary

- **ECATSL**: The Evidence-Constrained Adaptive Taint Specification Learning feature.
- **Candidate**: A proposed source, sink, sanitizer, or precondition rule that ECATSL has not accepted for compilation.
- **Candidate_Record**: An immutable, versioned record of a Candidate, including the Candidate type, confidence, evidence, counterexamples, applicability, CWE mapping, provenance, and state.
- **Evidence**: Machine-readable repository, catalog, static-analysis, or validation data linked to a Candidate_Record.
- **Counterexample**: Machine-readable validation data that contradicts, limits, or rejects a Candidate.
- **Applicability**: The language, framework, API signature, parameter positions, and scope conditions under which ECATSL evaluates a Candidate.
- **Provenance**: The origin, retrieval time, identifier or revision, content identity, and transformation history of data or decisions.
- **Constrained_Declarative_Specification**: A non-executable rule representation containing only accepted Candidate applicability and taint semantics.
- **Static_Analysis_Adapter**: An ECATSL integration that compiles a Constrained_Declarative_Specification for an existing HOS-LS InputTracer or CodeQL-oriented static-analysis capability.
- **Validation_Result**: A structured result returned by a Static_Analysis_Adapter or ECATSL input validation.
- **Path_Evidence**: A machine-verifiable static-analysis path that identifies an entry or source, propagation steps, a sink, and sanitizer absence or failure for the path.
- **Confirmed_Finding**: A finding that ECATSL marks confirmed because Path_Evidence satisfies the confirmation policy.
- **Explanatory_Support**: CWE or NVD catalog information attached to explain a finding's security classification without serving as vulnerability proof.
- **Unknown_API**: An API for which applicable existing HOS-LS capabilities cannot resolve taint role or Applicability.
- **LLM_Resolution_Attempt**: A conditional attempt to resolve an Unknown_API using a language model after every applicable existing HOS-LS capability completes or records an inapplicable, unavailable, or failed outcome.
- **Acceptance_Policy**: A versioned policy that defines evidence conditions for Candidate acceptance.
- **Validation_Policy**: A versioned policy that defines how a Validation_Result changes Candidate confidence or state.
- **Tooling_Resolution_Record**: A structured record of an applicable HOS-LS capability's input identity, outcome, cost, latency, and failure data for an API evaluation.
- **Benchmark_Manifest**: An immutable, versioned dataset description used to reproduce an ECATSL or comparison-baseline evaluation.
- **Catalog_Record**: A machine-readable NVD CVE, MITRE CWE, or compatible catalog-source record included in a Benchmark_Manifest, Candidate_Record, or Vulnerability_Knowledge_Database.
- **Vulnerability_Knowledge_Database**: A versioned local database containing imported, normalized, provenance-linked vulnerability and weakness records.
- **Catalog_Import**: A versioned ingestion of records from an identified NVD CVE, MITRE CWE, or compatible catalog source.
- **Normalization_Profile**: A versioned deterministic mapping from a source record to the local Vulnerability_Knowledge_Database representation.
- **Ingestion_Run**: A recorded execution that imports, verifies, normalizes, deduplicates, and reports a Catalog_Import.
- **Taint_Template**: A declarative source, sink, sanitizer, precondition, or propagation-hypothesis shape retrieved for a weakness mapping and subject to Candidate evidence and acceptance policies.
- **Discovery_Assistance**: Non-confirmatory generic analysis that uses repository, configuration, call-graph, static evidence, or vulnerability knowledge to rank Candidate hypotheses or identify possible endpoints and entrypoints.
- **Catalog_Evidence**: Imported vulnerability or weakness knowledge used as provenance-linked explanatory, retrieval, or hypothesis-ranking input that cannot establish controllability or a Confirmed_Finding.
- **Paired_Sample**: A vulnerable sample and its documented fixed or clean counterpart.
- **Project_Time_Group**: The documented project identifier and time partition assigned to a benchmark sample for split assignment.
- **Comparison_Baseline**: A named, versioned analysis configuration evaluated against the same Benchmark_Manifest.
- **Evaluation_Stratum**: A documented subset of benchmark samples defined by CWE, language, framework, project, or sample class.
- **Verified_Metric**: A precision, recall, or F1 value calculated from benchmark ground truth and findings whose confirmation status has been verified.
- **Audit_Cost**: Recorded human review effort assigned to a finding or evaluation stratum.
- **Reuse_Inventory**: A versioned record that maps each ECATSL capability to an existing HOS-LS abstraction, adapter, or explicitly documented capability gap.
- **Pipeline_Stage**: A named transformation from one versioned input artifact to one versioned output artifact.
- **Pipeline_Stage_Identity**: The current strict identity criteria for a Pipeline_Stage: versioned input artifact identities and types, transformation purpose, and versioned output artifact identities and types.
- **Operational_Complexity_Metric**: A recorded count of configured adapters, Pipeline_Stages, external service dependencies, and manual execution steps for an evaluation configuration.
- **Optimization_Experiment**: A versioned, paired evaluation that compares a baseline configuration and one changed configuration on the same Benchmark_Manifest and Evaluation_Strata.
- **Data_Quality_Report**: A versioned report of data provenance, integrity-check results, duplicate handling, completeness, validity, and exclusion counts for a dataset release.

## Requirements

### Requirement 1: Candidate Evidence and Provenance

**User Story:** As a security-analysis maintainer, I want every learned taint rule to have immutable, traceable support, so that rule acceptance is auditable and reproducible.

#### Acceptance Criteria

1. WHEN ECATSL proposes a source, sink, sanitizer, or precondition Candidate, THE ECATSL SHALL create a Candidate_Record containing the Candidate type, confidence value, Evidence references, Counterexample references, Applicability, CWE mapping, Provenance, and state.
2. IF Candidate_Record creation fails for a proposed Candidate, THEN THE ECATSL SHALL reject the Candidate proposal and record the Candidate_Record creation failure.
3. WHEN ECATSL records Evidence, a Counterexample, an Applicability change, a confidence change, or a state change for a Candidate, THE ECATSL SHALL create a new immutable Candidate_Record version that identifies the preceding version, update time, update cause, and changed data.
4. WHEN ECATSL retrieves or transforms Evidence, THE ECATSL SHALL record the Evidence origin, retrieval time, identifier or revision, content identity, and transformation history in Provenance.
5. WHEN a Candidate lacks Evidence that satisfies every applicable condition in the recorded Acceptance_Policy version, THE ECATSL SHALL retain the Candidate in an unaccepted state.
6. IF an accepted Candidate_Record no longer satisfies every applicable condition in the recorded Acceptance_Policy version, THEN THE ECATSL SHALL change the Candidate state to unaccepted before the Candidate enters Constrained_Declarative_Specification compilation.
7. WHEN a Counterexample contradicts a Candidate's taint role or Applicability, THEN THE ECATSL SHALL retain the Counterexample in the next Candidate_Record version and apply the recorded Validation_Policy version.

### Requirement 2: Declarative-Only Specification Compilation

**User Story:** As a security-analysis maintainer, I want only evidence-supported declarative taint rules to reach existing analysis adapters, so that analysis behavior remains constrained by verifiable evidence.

#### Acceptance Criteria

1. WHEN a Candidate satisfies every applicable condition in the recorded Acceptance_Policy version, has no rejection state, and has a proposed compilation input that passes input validation, THE ECATSL SHALL compile the Candidate into a Constrained_Declarative_Specification and record compilation-trigger and compilation-completion statuses.
2. WHEN a Candidate is unaccepted or rejected, THE ECATSL SHALL exclude the Candidate from Constrained_Declarative_Specification compilation.
3. WHEN Validation_Result data excludes a Candidate that a Static_Analysis_Adapter supports, THE ECATSL SHALL retain the Candidate_Record and Validation_Result while excluding the Candidate from Constrained_Declarative_Specification compilation.
4. THE ECATSL SHALL represent each compiled Candidate only as declared taint role, API signature, parameter positions, Applicability, and taint semantics supported by the Candidate Evidence.
5. WHEN input validation identifies executable logic, executable callbacks, runtime code generation, or taint semantics unsupported by accepted Candidate Evidence in a proposed compilation input, THE ECATSL SHALL reject the proposed compilation input.
6. WHEN ECATSL rejects a proposed compilation input, THE ECATSL SHALL retain the input-validation result in a Validation_Result linked to the applicable Candidate_Record and retain the linked Candidate_Record.
7. WHEN ECATSL submits a Constrained_Declarative_Specification for analysis, THE Static_Analysis_Adapter SHALL target an existing HOS-LS InputTracer or CodeQL-oriented static-analysis capability.
8. WHEN no Static_Analysis_Adapter is available for a Candidate or no available Static_Analysis_Adapter supports the Candidate's documented language or declared semantics, THE ECATSL SHALL record an unsupported-adapter Validation_Result and retain the Candidate without a Confirmed_Finding.

### Requirement 3: Static Validation Feedback and Candidate State

**User Story:** As a security-analysis maintainer, I want static-analysis feedback to update learned rules under a documented policy, so that unsupported rules are constrained before producing confirmed findings.

#### Acceptance Criteria

1. THE ECATSL SHALL maintain a versioned Validation_Policy that maps compilation errors, unreachable or no-path results, parameter mismatches, sanitizer evidence, and role-or-Applicability invalidation to a confidence update or rejection state.
2. WHEN a Static_Analysis_Adapter returns a compilation error, THE ECATSL SHALL store the error as a Validation_Result linked to the applicable Candidate_Record and apply the Validation_Policy.
3. WHEN a Static_Analysis_Adapter returns an unreachable or no-path result, THE ECATSL SHALL store the result as a Counterexample linked to the applicable Candidate_Record and apply the Validation_Policy.
4. WHEN a Static_Analysis_Adapter returns a parameter mismatch, THE ECATSL SHALL store a Counterexample containing the observed and declared parameter positions and apply the Validation_Policy.
5. WHEN a Static_Analysis_Adapter returns sanitizer evidence, THE ECATSL SHALL store the sanitizer evidence in the applicable Candidate_Record and apply the Validation_Policy.
6. WHEN a Validation_Result from a Static_Analysis_Adapter or another documented validation source invalidates a Candidate's declared role or Applicability, THEN THE ECATSL SHALL update Candidate confidence or rejection state according to the recorded Validation_Policy version.
7. IF application of a Validation_Policy fails, THEN THE ECATSL SHALL restore the Candidate to the state recorded before the failed policy application, continue processing with that restored state, and attempt to retain the policy-application failure in Candidate_Record Provenance.
8. WHEN ECATSL applies an Acceptance_Policy or Validation_Policy, THE ECATSL SHALL record the policy version, policy outcome, and input Evidence or Validation_Result identities in Candidate_Record Provenance.
9. IF Candidate_Record Provenance recording fails after a policy application, THEN THE ECATSL SHALL retain the policy outcome and flag the Candidate_Record version with the missing audit-trail element.

### Requirement 4: Static-Path-Gated Finding Confirmation

**User Story:** As a security reviewer, I want confirmed findings to have a minimal verifiable taint explanation, so that confirmation does not depend on unsupported assertions.

#### Acceptance Criteria

1. WHEN ECATSL marks a finding as a Confirmed_Finding, THE ECATSL SHALL attach Path_Evidence generated by a supported Static_Analysis_Adapter that includes sanitizer information documenting sanitizer absence or sanitizer failure and identifies an entry or source, ordered propagation steps, and a sink for the confirmed path.
2. WHEN a proposed finding lacks Path_Evidence generated by a supported Static_Analysis_Adapter, THE ECATSL SHALL classify the proposed finding as unconfirmed.
3. WHEN a proposed finding is supported only by an LLM natural-language assertion, Catalog_Evidence, or inferred endpoint or entrypoint information, THE ECATSL SHALL classify the proposed finding as unconfirmed.
4. WHEN ECATSL attaches CWE or NVD information to a finding, THE ECATSL SHALL label the information as Explanatory_Support and retain linked Catalog_Record Provenance.
5. WHEN Path_Evidence identifies a sanitizer that prevents propagation to the sink, THE ECATSL SHALL classify the proposed finding as unconfirmed for that path.
6. WHEN ECATSL successfully classifies a proposed finding as confirmed or unconfirmed, THE ECATSL SHALL retain each available applicable Candidate_Record version, Constrained_Declarative_Specification version, Validation_Result identity, and Path_Evidence identity with the classification.
7. IF retention of finding metadata fails after successful classification, THEN THE ECATSL SHALL retain the classification decision and flag the classification with each missing metadata element.
8. WHEN ECATSL assesses controllability or vulnerability status, THE ECATSL SHALL use Path_Evidence generated by a supported Static_Analysis_Adapter as the exclusive confirmation basis.

### Requirement 5: Existing-Tooling-First Conditional LLM Resolution

**User Story:** As a security-analysis maintainer, I want applicable HOS-LS capabilities to resolve APIs before language-model use, so that learning cost and unsupported assumptions remain controlled.

#### Acceptance Criteria

1. WHEN ECATSL evaluates an API for a Candidate, THE ECATSL SHALL complete execution or record an inapplicable, unavailable, or failed outcome for every applicable existing HOS-LS SAST, CodeQL, InputTracer, PureAI multi-agent, RAG, and NVD/CWE SQLite catalog capability before initiating an LLM_Resolution_Attempt.
2. WHEN an applicable existing HOS-LS capability resolves an API's taint role and Applicability, THE ECATSL SHALL record the resolution in a Tooling_Resolution_Record and SHALL not initiate an LLM_Resolution_Attempt for that API evaluation.
3. IF Tooling_Resolution_Record retention fails after an applicable existing HOS-LS capability resolves an API's taint role and Applicability, THEN THE ECATSL SHALL prevent an LLM_Resolution_Attempt for that API evaluation and flag the API evaluation with the missing Tooling_Resolution_Record.
4. WHEN every applicable existing HOS-LS capability completes with an unresolved outcome or records an unavailable, failed, or inapplicable outcome for an API, THE ECATSL SHALL classify the API as an Unknown_API and may initiate an LLM_Resolution_Attempt.
5. WHEN ECATSL records a HOS-LS capability outcome, THE ECATSL SHALL validate that the capability identity and version, input identity, start time, completion time, outcome, available cost, latency, and failure data are logically consistent before linking a Tooling_Resolution_Record containing those values to Candidate_Record Provenance.
6. WHEN an LLM_Resolution_Attempt completes, THE ECATSL SHALL record model identity, input identity, output identity, token count, monetary cost, latency, outcome, failure data, and linked unresolved Tooling_Resolution_Records in Candidate_Record Provenance.
7. WHEN an LLM_Resolution_Attempt fails or returns an assertion without validating Evidence, THE ECATSL SHALL retain the Candidate as unaccepted unless other Evidence satisfies every applicable condition in the recorded Acceptance_Policy version.

### Requirement 6: Narrow Initial Scope

**User Story:** As a product owner, I want the first release limited to a tractable attack surface, so that evidence rules and validation can be evaluated before expansion.

#### Acceptance Criteria

1. THE ECATSL SHALL document exactly one implementation language for the initial release.
2. THE ECATSL SHALL document two or three CWE mappings for the initial release, and each documented CWE mapping SHALL apply to the documented implementation language.
3. WHEN an analysis request targets a language or CWE mapping outside the documented initial scope, THE ECATSL SHALL return an out-of-scope result and stop downstream processing that has not completed before out-of-scope detection.
4. WHEN maintainers change the supported implementation language or CWE mappings, THE ECATSL SHALL create a versioned scope definition and record the change in Provenance.
5. IF version creation fails for a scope change, THEN THE ECATSL SHALL retain the scope-change Provenance and record the scope definition with an incomplete versioning state.

### Requirement 7: Reuse-First Minimal Footprint

**User Story:** As a HOS-LS maintainer, I want ECATSL to reuse existing abstractions and adapters before introducing new components, so that the feature has the smallest effective code footprint and avoids duplicate pipelines.

#### Acceptance Criteria

1. WHEN maintainers prepare to implement an ECATSL capability, THE ECATSL SHALL record a Reuse_Inventory entry that identifies the existing HOS-LS abstraction or adapter selected for the capability or the documented capability gap that prevents reuse.
2. WHEN a Reuse_Inventory entry identifies an existing HOS-LS abstraction or adapter that provides the required interface, THE ECATSL SHALL use the first identified matching abstraction or adapter for the corresponding capability.
3. WHEN maintainers introduce an ECATSL-specific abstraction or adapter, THE ECATSL SHALL record the unmet required interface, the Reuse_Inventory entries evaluated, and the distinct responsibility of the new abstraction or adapter.
4. WHEN two proposed ECATSL Pipeline_Stages match on every current Pipeline_Stage_Identity criterion, THE ECATSL SHALL retain exactly one Pipeline_Stage immediately and record the duplicate-stage decision.
5. IF ECATSL cannot consolidate Pipeline_Stages that match on every current Pipeline_Stage_Identity criterion, THEN THE ECATSL SHALL retain the matching Pipeline_Stages, record the consolidation failure, and permit the matching Pipeline_Stages to execute.
6. WHEN ECATSL produces a release or evaluation report, THE ECATSL SHALL report the Reuse_Inventory version and the Operational_Complexity_Metric values for configured adapters, Pipeline_Stages, external service dependencies, and manual execution steps.

### Requirement 8: Measured Efficiency and Evidence-Based Optimization

**User Story:** As a HOS-LS maintainer, I want runtime, token use, monetary cost, and operational complexity to be measured and optimized through controlled evidence, so that efficiency decisions do not rely on unsupported heuristics.

#### Acceptance Criteria

1. WHEN ECATSL executes an evaluation, THE ECATSL SHALL record wall-clock analysis latency, LLM token count, LLM monetary cost, configured adapter count, Pipeline_Stage count, external service dependency count, and manual execution-step count for the evaluation configuration.
2. WHEN maintainers propose an efficiency optimization, THE ECATSL SHALL define an Optimization_Experiment that identifies one baseline configuration, one changed configuration, the same Benchmark_Manifest version, the same Evaluation_Strata, and the measured metrics.
3. WHEN ECATSL completes an Optimization_Experiment, THE ECATSL SHALL retain the paired metric values, configuration identities, Benchmark_Manifest version, sample hashes, execution environment identity, and observed metric differences.
4. WHEN ECATSL reports an efficiency improvement with a linked completed Optimization_Experiment, THE ECATSL SHALL identify the completed Optimization_Experiment and the measured metric difference supporting the report.
5. WHEN ECATSL reports an efficiency improvement without a linked completed Optimization_Experiment, THE ECATSL SHALL report a non-zero measured metric difference and identify the missing Optimization_Experiment linkage.
6. WHEN an Optimization_Experiment does not show a measured improvement for a proposed optimization metric, THE ECATSL SHALL report the paired measured result without claiming optimization for that metric.
7. WHEN ECATSL selects a documented release configuration, THE ECATSL SHALL link the selection to the applicable completed Optimization_Experiment results and report the measured results and trade-offs in Verified_Metrics, runtime, token count, monetary cost, and Operational_Complexity_Metric.

### Requirement 9: Data Quality and Reproducible Benchmarking

**User Story:** As a security-analysis researcher, I want provenance-controlled, integrity-checked benchmark and catalog data, so that ECATSL evaluations are reproducible and data quality is visible.

#### Acceptance Criteria

1. WHEN ECATSL creates a benchmark or catalog dataset release, THE ECATSL SHALL create an immutable, versioned Benchmark_Manifest and Data_Quality_Report for that release.
2. THE Benchmark_Manifest SHALL record each Paired_Sample's vulnerable or fixed-or-clean classification, project identifier, source metadata, collection time, content hash, pair relationship, and Project_Time_Group.
3. THE Benchmark_Manifest SHALL record each Catalog_Record identifier or revision, source origin, retrieval time, content hash, and transformation history.
4. WHEN ECATSL ingests a benchmark sample or Catalog_Record, THE ECATSL SHALL verify the recorded content hash against the retrieved content, record a VERIFIED integrity-check outcome when the hashes match, and record a FAILED integrity-check outcome when the hashes do not match in the Data_Quality_Report.
5. WHEN ECATSL identifies two benchmark samples or Catalog_Records with the same content hash and data type, THE ECATSL SHALL retain one canonical record, record all duplicate identities, and report the duplicate count in the Data_Quality_Report.
6. WHEN ECATSL transforms benchmark or catalog data, THE ECATSL SHALL apply a documented deterministic transformation that produces the same output content hash for the same input content hashes and transformation version.
7. WHEN ECATSL completes a dataset release, THE ECATSL SHALL report record completeness, field-validity results, integrity-check failures, duplicate counts, excluded-record counts, and exclusion reasons in the Data_Quality_Report.
8. THE Benchmark_Manifest SHALL define immutable training, validation, and evaluation splits using Project_Time_Groups.
9. WHEN two benchmark samples have the same documented project identifier and time partition, THE ECATSL SHALL assign both samples to the same benchmark split.
10. WHEN any Benchmark_Manifest sample content, source metadata, Project_Time_Group, split definition, Catalog_Record content, ECATSL version, Constrained_Declarative_Specification version, Static_Analysis_Adapter version, or Comparison_Baseline configuration changes, THE ECATSL SHALL create a new immutable Benchmark_Manifest version with new hashes for changed artifacts.
11. WHEN ECATSL evaluates a Benchmark_Manifest, THE ECATSL SHALL retain the Benchmark_Manifest version, Data_Quality_Report version, manifest content identity, and evaluated sample hashes with the evaluation result.

### Requirement 10: Verified Metrics, Audit, and Evidence-Bounded Reporting

**User Story:** As a security-analysis maintainer, I want evaluation reports to quantify verified outcomes and operational cost, so that expansion decisions are based on auditable evidence.

#### Acceptance Criteria

1. WHEN ECATSL completes an evaluation, THE ECATSL SHALL calculate and report Verified_Metric values for precision, recall, and F1 from benchmark ground-truth labels and verified confirmation statuses of evaluated findings.
2. WHEN ECATSL completes an evaluation, THE ECATSL SHALL report each Verified_Metric for every Evaluation_Stratum containing at least one benchmark sample.
3. WHEN ECATSL reports a Verified_Metric, THE ECATSL SHALL identify the Benchmark_Manifest version, Data_Quality_Report version, Evaluation_Stratum definition, sample count, ground-truth label identities, finding classification identities, and Comparison_Baseline configuration used to calculate the Verified_Metric.
4. WHEN ECATSL completes an evaluation, THE ECATSL SHALL report Audit_Cost, analysis latency, LLM token count, LLM monetary cost, tooling failure count, LLM failure count, rejected-Candidate count, and Operational_Complexity_Metric values, including zero values, for the evaluation and for each Evaluation_Stratum containing at least one benchmark sample.
5. WHEN ECATSL completes an evaluation that lacks sufficient verified evidence for a comparison, THE ECATSL SHALL report the measured metrics and identify the evidence limitation without asserting performance superiority.
6. WHEN ECATSL reports a comparison-baseline result, THE ECATSL SHALL identify the Comparison_Baseline name, version, configuration identifier, Benchmark_Manifest version, and Evaluation_Strata used for the comparison.
7. WHEN ECATSL asserts performance superiority, THE ECATSL SHALL identify the recorded verified evidence supporting the assertion and state the limitations of that evidence in the report.


### Requirement 11: Versioned Local Vulnerability Knowledge and Generalizable Discovery

**User Story:** As a security-analysis maintainer, I want a provenance-controlled local vulnerability knowledge database and generalizable evidence-based discovery assistance, so that ECATSL can rank reusable hypotheses without requiring per-route maintenance or treating catalog knowledge as vulnerability proof.

#### Acceptance Criteria

1. WHEN ECATSL imports available NVD CVE, MITRE CWE, or compatible catalog-source records, THE ECATSL SHALL create a versioned Catalog_Import in the Vulnerability_Knowledge_Database that records the source origin, source identifier or revision, retrieval time, retrieved-content identity, license or usage metadata when supplied by the source, and import-tool version.
2. WHEN ECATSL normalizes a Catalog_Import record, THE ECATSL SHALL apply the recorded Normalization_Profile and retain the source-record identity, normalized-record identity, normalization-profile version, and transformation history in Provenance.
3. WHEN ECATSL applies the same Normalization_Profile version to records with identical source content identities, THE ECATSL SHALL produce normalized records with identical content identities.
4. WHEN ECATSL identifies imported or normalized vulnerability-knowledge records with the same canonical identifier and record type or the same normalized content identity and record type, THE ECATSL SHALL retain one canonical record, retain all duplicate source identities, and record the deduplication decision.
5. WHEN ECATSL completes an Ingestion_Run, THE ECATSL SHALL create a versioned integrity and completeness report containing retrieved-record count, imported-record count, normalized-record count, canonical-record count, duplicate count, missing-required-field count, integrity-check outcomes, excluded-record count, exclusion reasons, source coverage, and Catalog_Import identities.
6. WHEN ECATSL repeats an Ingestion_Run with the same source-record identities, content identities, Normalization_Profile version, and import-tool version, THE ECATSL SHALL retain the existing canonical records and report zero newly created canonical records.
7. WHEN ECATSL receives a Catalog_Import containing records that are new or changed since the latest completed Ingestion_Run for the same source, THE ECATSL SHALL ingest only the new or changed records and create a new versioned Ingestion_Run report.
8. WHEN ECATSL receives a weakness identifier within the documented initial CWE scope, THE ECATSL SHALL retrieve provenance-linked Taint_Templates ranked by semantic weakness-to-template relevance, documented Applicability, and available Catalog_Evidence.
9. WHEN ECATSL uses the Vulnerability_Knowledge_Database for Candidate generation or ranking, THE ECATSL SHALL label the resulting Candidate hypotheses with Catalog_Evidence and retain the related record, retrieval, and ranking Provenance.
10. WHEN ECATSL performs Discovery_Assistance over repository, configuration, call-graph, or static evidence, THE ECATSL SHALL permit framework-agnostic automated endpoint and entrypoint discovery and Candidate hypothesis ranking without requiring user-authored per-route configuration.
11. WHEN ECATSL evaluates route or entrypoint discovery logic, THE ECATSL SHALL reject low-efficiency, brittle, enumerated hard-coded route rules or patterns that require users to maintain individual routes and do not generalize across supported repository evidence.
12. WHEN Catalog_Evidence or Discovery_Assistance identifies a candidate source, sink, sanitizer, precondition, endpoint, or entrypoint, THE ECATSL SHALL retain the result as a non-confirmatory Candidate hypothesis, classify any associated proposed finding as unconfirmed when no Path_Evidence is produced, and prevent the hypothesis from becoming a Confirmed_Finding until the applicable Acceptance_Policy and supported Static_Analysis_Adapter produce Path_Evidence.
13. WHEN ECATSL uses imported catalog records, generic Candidate generation, API or source, sink, sanitizer, or precondition hypothesis ranking, or framework-agnostic entrypoint discovery assistance, THE ECATSL SHALL preserve the existing Candidate evidence, Provenance, reuse-first, initial language and CWE scope, and Static-Path-Gated Finding Confirmation requirements.