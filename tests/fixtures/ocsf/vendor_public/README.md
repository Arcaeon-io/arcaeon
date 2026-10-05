# OCSF Detection Finding: public sample

Source: https://github.com/ocsf/examples/blob/ce0589ece917e9b9c018b795c8979ffb42072cad/mappings/markdown/Okta/v1.3.0/System%20Logs/Detection%20Finding/samples/detection_finding.ocsf
Commit: ce0589ece917e9b9c018b795c8979ffb42072cad
Retrieved: 2026-10-05
Licence: not stated. The ocsf/examples repo has no LICENSE file (the OCSF
schema itself is Apache-2.0). Kept as one test sample; drop it if that is not
acceptable.
Trimming: none; file bytes verbatim, renamed `.ocsf` -> `.ocsf.json`.
Redaction: none (the IPs are private-range placeholders, no person named).

| file | what it is |
|---|---|
| `okta_detection_finding.ocsf.json` | an OCSF 1.3.0 Detection Finding (class 2004) mapped from an Okta System Log event |

Arcaeon has no OCSF ingest: `arcaeon.prove.ocsf` exports. The test compares our
1.3.0 export with this sample: `class_uid`, `category_uid`, `category_name`,
`activity_id`, `type_uid` and `metadata.version` agree. Result: pass, no change.

Note on the sample (not on us): it writes `class_name: "Detection Findings"`;
the 1.3.0 schema caption, and our export, say `Detection Finding`.
