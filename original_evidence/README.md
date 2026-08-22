# Original archive evidence

This directory preserves the relevant contents of the supplied `DFD.zip` as historical evidence. Artifact bytes have not been edited. Only their locations changed so source, models, reports, and figures can be reviewed separately.

The source archive was read without modification. Its recomputed SHA-256 is:

```text
844167c9f3890357c4570fedfd2ff945666383867373975fd8c7945765dfbd0f  DFD.zip
```

The digest matches the value supplied with the project brief. Before extraction, all 51 entry names and external attributes were checked. No absolute paths, drive-qualified paths, parent-directory traversal segments, NUL characters, or symbolic-link entries were present.

## Disposition

The archive contains 51 records: 44 files and seven directory records. The curated evidence retains 27 byte-distinct, relevant files:

| Area | Files | Contents |
|---|---:|---|
| `source/` | 12 | Parser, matcher, DREAD scorer, rule data, report and countermeasure generators, demos, and the original README |
| `models/` | 2 | The general sequence model and the intentionally insecure notes-application model |
| `reports/` | 4 | Two parser reports, the historical HTML threat report, and the historical nine-finding JSON report |
| `figures/` | 9 | The rendered sequence diagram and eight mitigation figures |

The other 24 records are documented but not copied into the curated evidence:

- Seven directory records contain no file content.
- Four files are exact duplicate copies. The sequence diagram PNG appears three times under the outer archive, as does the sequence report HTML; the `DFD/SFD/` copy is authoritative in each case.
- Three nested ZIP files contain only byte-identical copies of artifacts retained separately.
- Ten `.pyc` files are generated Python bytecode. Their corresponding source files are retained.

[`MANIFEST.json`](MANIFEST.json) maps every original archive entry to its disposition. [`MANIFEST.sha256`](MANIFEST.sha256) contains a checksum for every retained evidence file. Directory records use a `null` hash consistently because they have no payload.

## Historical report status

[`reports/threat_report_20250710_152215.json`](reports/threat_report_20250710_152215.json) is the original nine-finding generated result, preserved exactly with SHA-256 `a7cf32744c63917f3a20e9b8a09d745f67b8cca8cb520ea7b07188129633599d`.

It is historical output, not a current validated risk assessment. Its severities reflect the original heuristic matcher and DREAD implementation, including code that forced the first two ranked results to `Critical`. The original HTML reports are also unchanged. Because the curation separates reports from figures, relative image references embedded in those historical HTML files may not resolve; the referenced images remain available under `figures/`.

## Sensitivity review

The retained source and text artifacts were searched for secrets, credentials, tokens, private URLs, email addresses, IP addresses, personal filesystem paths, and internal hostnames. PNG metadata and visible content were also reviewed. No content requiring isolation or redaction was identified.

Two non-sensitive network references remain unchanged: a public PlantUML rendering URL in `source/plantuml_parser.py` and `localhost` Redis examples embedded in `source/threat_modeling/countermeasures.py`. The former means that running the historical parser with its optional PlantUML dependency can send a diagram to a public rendering service. Do not use that historical rendering path for confidential models.

This was a pattern-based and visual review, not a substitute for an organizational data-classification process. If later provenance information identifies an artifact as restricted, isolate the unchanged file and document any separately produced redacted derivative rather than rewriting this evidence set.
