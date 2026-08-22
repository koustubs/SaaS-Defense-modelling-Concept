# Original work assessment

## Scope and status

The supplied material is best understood as an early proof of concept for deriving security observations from PlantUML sequence diagrams. It combines a general diagram parser with a notes-application threat matcher, a DREAD ranking component, generated JSON and HTML, countermeasure guidance, and mitigation figures.

This assessment describes what the preserved code and artifacts demonstrate. It does not establish who authored individual files, whether the proposed controls were deployed, or whether the sample system represents a production service. The unchanged evidence is catalogued in [`../original_evidence/MANIFEST.json`](../original_evidence/MANIFEST.json).

## What the project attempted

The original work formed two related pipelines:

1. `plantuml_parser.py` read a sequence diagram, extracted structural elements, optionally rendered the model, and produced an HTML inventory.
2. `threat_matcher.py` parsed a notes-application diagram, applied a JSON rule set, attached static DREAD values, and emitted a finding report. Separate modules added HTML presentation and countermeasure material.

The archive includes two models with different purposes. `sample_sequence.uml` depicts a broad SaaS design involving authentication, notes CRUD, synchronization, cleanup, monitoring, notification, OWASP ZAP, Kafka, and MISP/TAXII. `sample_notes_app.uml` is an intentionally insecure example that labels omissions such as unauthenticated note retrieval, missing input validation and audit logging, missing rate limiting, excessive error detail, no MFA, repeated login attempts without lockout, and no new-device notification.

The generated artifacts show that the pipeline was exercised: parser HTML and PNG output, a nine-finding JSON report dated 2025-07-10, a corresponding HTML threat report, and eight mitigation figures are present. These artifacts demonstrate report generation, not implementation of the depicted services or controls.

## PlantUML extraction

The general parser used regular expressions to extract:

- a `title` line;
- quoted `actor` declarations with aliases;
- quoted `participant` declarations with aliases;
- request messages using `->`;
- response messages using `-->`; and
- section labels delimited by `==`.

This was a useful, small parser for the supplied examples, but it supported only a subset of PlantUML. It did not build an abstract syntax tree, retain source line numbers, associate interactions with sections or control blocks, or report unsupported syntax. It recognized only the declaration forms encoded in its regular expressions. Requests and responses were collected in separate passes, so the output grouped requests before responses instead of preserving full chronological order.

The parser mixed library, command-line, rendering, and report concerns. Errors were commonly printed and converted to `False`, while the command path used `sys.exit()`. Paths and temporary files depended on the current working directory. When the optional `plantuml` package was available, rendering used an unencrypted public PlantUML endpoint; running that path could disclose a model outside the local environment. Generated HTML interpolated model-derived values without escaping them.

## Rule-based matching and STRIDE representation

`threat_rules.json` contains 47 rules. Eleven use conventional STRIDE-prefixed identifiers across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. The remainder add notes-specific, authentication, authorization, session, logging, configuration, data-protection, input/output, business-logic, privacy, notification, and user-experience categories.

The matcher did not execute all 47 rules generically. It dispatched a limited set of rule IDs to handwritten checks and implemented special cases for selected `SAAS-NOTES` IDs. Several categories and rule IDs in the JSON therefore had no effective evaluation path.

The implemented checks searched interaction text for keywords such as `login`, `token`, `validate`, `rate`, `limit`, `delete`, and `export`. They then inferred a missing control from the absence of another keyword. This made the approach transparent and easy to demonstrate, but it was heuristic:

- Authentication, validation, logging, access-control, rate-limit, and privilege checks were often diagram-global. A control mentioned for one component or flow could suppress findings for unrelated flows.
- Conversely, a control expressed through an unrecognized phrase, note, guard, stereotype, or included model could be treated as absent.
- `STRIDE-D-001` and `STRIDE-D-002` both called the same rate-limit check, producing overlapping findings from the same evidence.
- `STRIDE-E-002`, titled “Session management without proper timeout,” called the audit-logging check. The historical timeout finding therefore cites missing logging rather than timeout evidence.
- The privilege check treated words such as `delete` and `export` as administrative actions regardless of actor, resource ownership, or endpoint semantics.
- Likelihood was set to `High` when more than two evidence strings were collected and `Medium` otherwise. Evidence count is not a calibrated likelihood measure.
- Finding identifiers depended on rule iteration order and did not identify a source line, interaction, trust boundary, or affected asset.

The parser and matcher nevertheless established a useful pattern: stable rule identifiers, human-readable evidence, explicit mitigations, and machine-readable output. Those concepts are suitable for reuse once parsing, rule validation, contextual evaluation, and risk calibration are separated.

## Historical DREAD scoring

The original scorer assigned a hard-coded five-part DREAD tuple to each known rule ID and defaulted unknown IDs to five in every dimension. It calculated both a simple average and a weighted average. The weighting favored Damage and Affected Users, followed by Exploitability and Discoverability, with Reproducibility weighted least. Its nominal thresholds were:

| Weighted score | Nominal severity |
|---:|---|
| 8.0–10.0 | Critical |
| 6.0–7.99 | High |
| 4.0–5.99 | Medium |
| Below 4.0 | Low |

After sorting, the scorer explicitly changed the first two findings to `Critical` even when their weighted scores were below the Critical threshold. In the preserved report, both top findings have a weighted score of 7.27 but are labelled Critical because of that override.

Some DREAD mappings also drifted from the rule data. For example, `SAAS-NOTES-010` is a new-device notification rule in the JSON but is commented as password-strength feedback in the scorer; `SAAS-NOTES-011` is plaintext note storage in the JSON but is commented as session timeout; and `SAAS-NOTES-018` is password-strength feedback in the JSON but is commented as input sanitization. Further mappings similarly diverge, and the scorer contains `SAAS-NOTES-020` although the rule file stops at `SAAS-NOTES-019`.

DREAD is retained here because it records the historical prioritization method. Its values should not be treated as objective vulnerability measurements. The dimensions require assumptions about deployment, attacker capability, population, compensating controls, and business impact that a sequence diagram alone does not provide. Hard-coded values, an unknown-rule default, semantic ID drift, and the rank override further reduce comparability. A modern register should instead document evidence, preconditions, likelihood rationale, impact rationale, and residual risk using one consistently applied qualitative matrix.

## Reports and countermeasure material

The original JSON report recorded metadata, a DREAD summary, findings, evidence strings, mitigations, status, and rank. The HTML generator added severity and category filters, DREAD details, countermeasure cards, and links to mitigation figures. The separate parser report summarized actors, participants, interactions, and sections.

Finding, rule, model, and countermeasure values were inserted directly into HTML attributes and content without escaping. A malicious diagram, rules file, or imported JSON result could therefore create active HTML or script content in a generated report. Timestamps also made output nondeterministic, and image lookup depended on the current working directory.

`countermeasures.py` associates nine historical finding IDs with 11 countermeasure records. Each record can include priority, effort, estimated time, dependencies, implementation steps, code fragments, test ideas, and monitoring ideas. The eight PNG figures illustrate lockout/CAPTCHA, rate limiting, MFA, password feedback, RBAC, quotas, safe error handling, and session timeout.

This material is useful as a control-design backlog and as evidence that mitigation options were considered. It is not proof that the controls work. Several entries propose external infrastructure or contain incomplete illustrative fragments, and the effort estimates have no recorded estimation basis. The preserved “tests” and demos primarily print status, generate files, and return booleans; they do not make automated security assertions.

## Review of the nine historical findings

The historical report is preserved exactly at [`../original_evidence/reports/threat_report_20250710_152215.json`](../original_evidence/reports/threat_report_20250710_152215.json). The following table calibrates what each result can support without rewriting the historical output.

| Historical ID | Observation type | Assessment of support |
|---|---|---|
| `TF-SD-003` | Security/resilience: resource exhaustion | Plausible design concern, but its 14 evidence items are identical to `TF-SD-002`. It is not independently demonstrated and may duplicate the rate-limit finding. |
| `TF-SD-004` | Security: authorization/elevation of privilege | Authorization is important, but the matcher classified normal user actions containing `delete` or `export` as administrative. The cited flow does not establish an admin privilege boundary or a source-code bypass. |
| `TF-SD-002` | Security/resilience: endpoint rate limiting | The insecure model explicitly notes missing rate limiting on one export flow. Extending that conclusion to every API-like interaction is heuristic. It overlaps `TF-SD-003`. |
| `TF-SD-005` | Security: session lifetime | Weakly supported and misclassified. Its evidence concerns missing audit logging, because the timeout rule invokes the logging checker. No timeout interaction is cited. |
| `TF-SD-001` | Security/privacy: error disclosure | The model deliberately returns an over-specific database error. The example exposes a field name, not a password value or credential, so the report’s “sensitive data” wording may overstate the demonstrated disclosure. Generic external errors remain an appropriate control. |
| `TF-SD-006` | Security hardening: MFA | The sample explicitly labels a login as lacking 2FA. This supports a modelled control gap, but not a claim that an implementation lacks MFA. Whether MFA is required affects severity. |
| `TF-SD-007` | Security: brute-force resistance | The explicit ten-attempt loop and no-lockout comment provide good diagram-level support for the intended insecure scenario. They do not demonstrate application behavior without executable code or tests. CAPTCHA is one option, not a required consequence of this finding. |
| `TF-SD-009` | Usability with security relevance | A visual password-strength indicator is feedback, not server-side password-policy enforcement. Treating its absence as a scored vulnerability mixes usability with security assurance. |
| `TF-SD-008` | Detection/resilience and usability | A new-device notification can improve account-compromise detection, but its absence does not create authentication bypass by itself. It should be tracked separately from directly exploitable vulnerabilities. |

The report therefore contains meaningful review signals, but the count of nine should not be read as nine independently validated vulnerabilities. Two availability findings duplicate the same evidence, one timeout finding uses unrelated evidence, one authorization finding overgeneralizes action keywords, and two user-experience observations belong outside a vulnerability count.

## What was technically useful

- The archive preserves both a broad architecture model and a deliberately insecure test model.
- Rule and finding records already contain identifiers, categories, impact text, recommendations, and evidence fields.
- The use of JSON rules and JSON output provides a basis for schema validation and deterministic report generation.
- STRIDE supplied a recognizable discovery taxonomy, while the additional categories acknowledged operational, privacy, and usability concerns.
- Countermeasure records connect findings to implementation, test, and monitoring ideas, even though those ideas still require validation.
- Generated reports and figures provide evidence of an end-to-end prototype workflow.

## Corrections required for a defensible implementation

The modernization should retain the useful concepts while correcting the following issues verified in the evidence:

1. Remove the duplicate `DREADScorer` import in `threat_matcher.py`.
2. Parse a documented PlantUML subset in source order and retain line- or interaction-level evidence.
3. Validate the rule schema, reject duplicate or unknown identifiers, and keep rule semantics and risk mappings together.
4. Evaluate controls in the relevant flow, actor, component, and trust-boundary context rather than using diagram-global presence flags.
5. Separate security, privacy, resilience, and usability observations and avoid counting the latter as vulnerabilities.
6. Replace evidence-count likelihood and category-default severity with documented likelihood and impact rationale.
7. Remove rank-based severity manipulation; ranking must not override declared thresholds.
8. HTML-escape all model-, rule-, and finding-derived content, including attribute values and filter data.
9. Raise typed exceptions from reusable modules. Reserve process exit codes for command-line entry points and resolve paths independently of the current directory.
10. Replace print-based demonstrations with automated assertions for parsing, schema validation, contextual matching, deterministic output, and HTML escaping.
11. Treat the countermeasure fragments as design notes unless a runnable implementation and tests substantiate them.
12. Keep external systems out of runtime claims unless adapters and infrastructure are present and exercised.

In particular, OWASP ZAP is an out-of-band dynamic testing tool; the original broad model should not send each note to ZAP for runtime “cleaning.” MISP/TAXII can enrich monitoring with threat intelligence, but it should not inspect ordinary note content. Kafka, SIEM, OAuth, JWT, notification, and scanning components in a diagram are architectural proposals, not evidence of integration.

## Diagram evidence versus implementation evidence

A sequence diagram records selected interactions at a chosen level of abstraction. If a control is absent, the defensible conclusion is normally that the diagram does not show the control. That absence can justify a review question or a design finding, but it does not prove the running application lacks the control. Controls may be implemented in middleware, infrastructure, framework defaults, database policy, or code outside the model.

The converse also matters: writing “validate token,” “RBAC,” or “rate limit” in a diagram does not prove correct enforcement. Confirmation requires source inspection, configuration review, runtime tests, or other implementation evidence.

`sample_notes_app.uml` is stronger evidence of the author’s intended insecure scenario because it explicitly annotates several omissions. Even there, the evidence supports statements about the model, not an unseen production system. The modernized project should preserve this distinction in finding status and traceability: model observation, implementation hypothesis, demonstrated control, and validated test result are different evidence states.
