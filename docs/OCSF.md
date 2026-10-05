# OCSF export: one verdict as one Detection Finding

`arcaeon envelope export-ocsf` turns one arcaeon verdict into one event in
the Open Cybersecurity Schema Framework (OCSF), so a security team sees a
BROKEN handoff in the SIEM it already watches. The library is
`arcaeon.prove.ocsf.to_ocsf(obj, now=None, include_verified=False)`.

It reads one of three inputs, all JSON:

- an `arcaeon envelope verify` report (the JSON it prints on stdout);
- an `arcaeon gate decide --json` decision (`GateDecision.to_dict()`);
- a gate evidence pack's `evidence.json` (the only input that carries the
  handed file's sha256: the gate hashes the bytes as it copies them).

Any other report with a `verdict` of VERIFIED, BROKEN or COULD NOT LOOK (for
example `arcaeon verify --json` on a ledger) is read as a verify report, with
fewer fields filled. Anything else is refused: COULD NOT LOOK, exit 3,
nothing exported.

## Schema version and where it was read

The mapping was read on 2026-10-04 from the OCSF schema server, which
answered version **1.9.0** (`metadata.version` in every event). The pages:

- https://schema.ocsf.io/classes/detection_finding (the class page)
- https://schema.ocsf.io/api/classes/detection_finding (the same class as JSON; read with all profiles and again with `?profiles=` for the class alone)
- https://schema.ocsf.io/api/objects/finding_info
- https://schema.ocsf.io/api/classes/base_event
- https://schema.ocsf.io/api/objects/metadata
- https://schema.ocsf.io/api/objects/product
- https://schema.ocsf.io/api/objects/evidences
- https://schema.ocsf.io/api/objects/file
- https://schema.ocsf.io/api/objects/fingerprint
- https://schema.ocsf.io/api/data_types (`timestamp_t`: milliseconds since the epoch)
- https://schema.ocsf.io/api/version

What the class says, as read:

- Detection Finding is `class_uid` 2004 in category Findings, `category_uid` 2.
- Required with no profile applied: `activity_id`, `category_uid`, `class_uid`, `finding_info`, `metadata`, `severity_id`, `time`, `type_uid`. `metadata` requires `product` and `version`; `finding_info` requires `uid`.
- `type_uid` "must" be computed as `class_uid * 100 + activity_id`; Create is `activity_id` 1, so 200401.
- `severity_id`: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other.
- `status_id`: 0 Unknown, 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 5 Archived, 6 Deleted, 99 Other.
- `time` is a `timestamp_t`: integer milliseconds since 1970-01-01 UTC, the finding's creation time.
- `verdict`, `verdict_id` (incident profile), `disposition_id` and `action_id` (security_control profile), `cloud` (cloud profile) and `osint` (osint profile) belong to profiles. The export applies no profile (`metadata.profiles` is `[]`), so it uses none of them.

## The mapping

| verdict | severity_id | is_alert | emitted |
|---|---|---|---|
| BROKEN | 4 (High) | true | always: a finding |
| COULD NOT LOOK | 2 (Low) | false | always, with what was not checked |
| COULD NOT LOOK on a gate refusal (`decision` is `refuse`) | 3 (Medium) | true | always, with what was not checked |
| VERIFIED | 1 (Informational) | false | only with `--include-verified` (library: `include_verified=True`); by default nothing is printed and the exit is 0 |

VERIFIED is skipped by default because a SIEM is a place for things to look
at; a stream of "this was fine" findings buries the BROKEN ones. Turn it on
when the SIEM is also the audit record.

A COULD NOT LOOK that the gate turned into a refusal (an act, pay or
irreversible it stopped) is an alert at Medium; one that allowed a read, and
a bare verify report, stay Low.

A gate refusal is never skipped and never reads as passed, whatever the
envelope said. The gate can refuse a VERIFIED envelope: a checker row says
BROKEN for the same bytes (`checker-broken`), a `--checks` file or the
envelope's `checks[]` could not be read (`checks-unreadable`), or the
non-party check rule was not met (`nonparty-check`). For a gate decision or
evidence pack whose `decision` is `refuse` and whose verdict is VERIFIED, the
event reports the word the gate's exit code means:

| gate veto | `status_code`, severity, is_alert | gate exit |
|---|---|---|
| `checker-broken` | BROKEN, 4 (High), true | 1 |
| `checks-unreadable`, `nonparty-check` (or any other refusal of a VERIFIED envelope) | COULD NOT LOOK, 3 (Medium), true | 3 |

`unmapped.arcaeon.verdict` still says VERIFIED (the envelope's own word), and
`unmapped.arcaeon.veto` names the veto. The title names the refused action
and the veto, e.g. `BROKEN: a checker says BROKEN for grades.csv; pay refused
(checker-broken)`.

Every event, whatever the verdict:

| OCSF attribute | value | from |
|---|---|---|
| `class_uid`, `class_name` | 2004, Detection Finding | fixed |
| `category_uid`, `category_name` | 2, Findings | fixed |
| `activity_id`, `activity_name` | 1, Create | fixed: each export is a new finding |
| `type_uid`, `type_name` | 200401, Detection Finding: Create | `class_uid * 100 + activity_id` |
| `severity_id`, `severity` | see the tables above | the verdict, or the gate's veto on a refusal |
| `status_id`, `status` | 1, New | fixed |
| `status_code` | `VERIFIED`, `BROKEN` or `COULD NOT LOOK` | the three-word verdict, as "the source-specific status code"; never VERIFIED on a gate refusal |
| `status_detail` | the verify reason | report `reason` |
| `is_alert` | see the tables above | the verdict, or the gate's veto on a refusal |
| `time` | integer milliseconds | the export time (`--now` fixes it) |
| `timezone_offset` | 0 | `time` is UTC |
| `message` | `<verdict>: <file name>` | |
| `metadata.version` | `1.9.0` | the schema read above |
| `metadata.profiles` | `[]` | no profile applied |
| `metadata.product` | `name` arcaeon, `vendor_name` arcaeon, `version` the installed arcaeon | |
| `finding_info.uid` | `arcaeon-` and 32 hex | sha256 of the normalized input; the same check gives the same uid |
| `finding_info.title` | e.g. `BROKEN: grades.csv failed its arcaeon check` | |
| `finding_info.desc` | the verdict, the reasons, what was not checked, then the limits line | |
| `finding_info.created_time` | same as `time` | |
| `finding_info.types` | `["arcaeon verify report"]`, `["arcaeon gate decision"]` or `["arcaeon gate evidence pack"]` | which input it was |
| `evidences[].file` | `name`, `type_id` 1 (Regular File), `type`, `size` (sealed bytes), `hashes` (`algorithm_id` 3, SHA-256) | the handed file, then the envelope; `hashes` only when the input carries the sha256 |
| `unmapped.arcaeon` | everything below | |

OCSF has no attribute for these, so they go in `unmapped.arcaeon` (OCSF:
"a container for source-specific attributes that do not map to any defined
OCSF attribute"): `verdict`, `source`, `reason`, `reasons`,
`could_not_check` (`looked_for`, `where` as a file name, `reason_word`),
`not_checked`, `steps`, `file`, `file_sha256`, `file_sha256_of`,
`envelope`, `envelope_sha256`, `label`, `sealed_by`, `sealed_at`,
`sealed_for` (the binding: audience, deal, purpose, not_after),
`signers_valid` (keys whose signature checked), `signers_named` (keys the
receiver named, when the input records them), `audience_checked`,
`deal_checked`, `purpose_checked`, `action`, `decision`, `gate_reason`,
`checked_at`, `evidence` (the evidence pack's directory name), `note` and
`limits`. A gate decision or evidence pack that carries the `--checks` answer
or the non-party rule's answer adds `veto`, `checks` (`veto`, `files`,
`rows`, `file_sha256`, `problems`, `broken_count`, and `broken`: each row
that said BROKEN by `checker`, `vendor_id`, `vendor_word`, `subject`,
`attestation`, `reported_by`, `source`, `file` and `line`, never the row's
payload; at most 100 listed) and `nonparty_check` (`rule`, `cap`, `amount`,
`applies`, `satisfied`, `veto`). A verify report has none of the three. No
OCSF field name is invented: every attribute outside `unmapped`
is one the 1.9.0 class, `finding_info`, `metadata`, `product`, `file` or
`fingerprint` lists.

The file sha256 is in the event only when the input has it. An `envelope
verify` report and a gate decision do not carry it (verify compares it and
reports a mismatch in words); a gate `evidence.json` does. With the other
inputs `hashes` is left out and `unmapped.arcaeon.file_sha256` is null.

## Paths never leave

Only file names reach the event: the handed file, the envelope, where a
COULD NOT LOOK looked and the evidence pack all become their last path part.
Every string is then scrubbed of the input's own directories and of any
absolute path (`C:\...`, `C:/...`, `\\server\...`, `/...`), so a reason that
quotes a path keeps only the name. URLs and `urn:` refs are left alone.

## The limits line

Every event's `finding_info.desc` ends with this, word for word:

Limits: VERIFIED means the bytes are unchanged since the named key sealed them and are labeled for this receiver; it never means the content is true or safe. BROKEN means a check came out wrong, not who is at fault. COULD NOT LOOK means something was not checked; it vouches for nothing.

What a VERIFIED does not prove is in [ENVELOPE.md](ENVELOPE.md). The export
adds nothing to the check: it restates the verdict in OCSF's words and sends
nothing anywhere. Delivering the event to a SIEM is the caller's job.

## Use

```console
$ arcaeon envelope verify grades.csv --audience instructor-1 --signer did:key:z6Mk... > report.json
$ arcaeon envelope export-ocsf report.json --out finding.json
finding.json
$ arcaeon gate decide --envelope grades.csv.envelope.json --audience instructor-1 --signer did:key:z6Mk... --action pay --json | arcaeon envelope export-ocsf -
```

Exit codes: 0 exported (or VERIFIED skipped), 3 the input is not a readable
arcaeon verdict (nothing exported), 2 bad usage. The exit code is about the
export, not the verdict: read the verdict from `status_code`. Given the same
input and the same `--now`, the output is byte-identical (sorted keys).

## 1.3 compatibility mode

`--ocsf-version 1.3.0` (library: `to_ocsf(..., ocsf_version="1.3.0")`)
writes the same finding stamped `metadata.version` `1.3.0` and cut down to
the attributes OCSF 1.3.0 has. Without the flag, or with `--ocsf-version
1.9.0`, the output is byte-for-byte what it was before the flag existed.

Why 1.3.0: two places that take OCSF stop there.

- Amazon Security Lake custom sources: "For custom sources, Security Lake supports OCSF version 1.3 and earlier", as Parquet (https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html).
- Datadog Observability Pipelines, "Remap to OCSF": the prebuilt library mappings cover OCSF 1.1.0 to 1.3.0 (https://docs.datadoghq.com/observability_pipelines/processors/remap_ocsf/).

What changes in 1.3.0 mode. The code keeps an allowlist
(`arcaeon.prove.ocsf.OCSF_13_ALLOW`), not a denylist: anything not on it is
dropped, so a field added to the 1.9.0 event later stays out of 1.3.0 mode
until someone checks it against the 1.3.0 pages and adds it. The allowlist
was read on 2026-10-05 from these pages, with no profile applied:

- https://schema.ocsf.io/1.3.0/api/classes/detection_finding
- https://schema.ocsf.io/1.3.0/api/objects/finding_info
- https://schema.ocsf.io/1.3.0/api/objects/metadata
- https://schema.ocsf.io/1.3.0/api/objects/product
- https://schema.ocsf.io/1.3.0/api/objects/evidences
- https://schema.ocsf.io/1.3.0/api/objects/file
- https://schema.ocsf.io/1.3.0/api/objects/fingerprint

As read there: Detection Finding is class_uid 2004 in 1.3.0, with the same
required attributes (`activity_id`, `category_uid`, `class_uid`,
`finding_info`, `metadata`, `severity_id`, `time`, `type_uid`); Create is
activity_id 1, so type_uid is still 200401; severity_id 4/3/2/1 and status_id 1
(New) mean the same; `finding_info` requires `uid` and `title`, `product`
requires `vendor_name`, `file` requires `name` and `type_id`, `fingerprint`
requires `algorithm_id` and `value` (3 is SHA-256). So class_uid,
category_uid, activity_id, type_uid, severity_id, status_id, status_code,
finding_info, evidences and unmapped are identical in both modes.

Dropped in 1.3.0 mode:

- `is_alert`: not in the 1.3.0 class. A BROKEN finding still has severity_id 4 (High), a COULD NOT LOOK refusal 3 (Medium), and `unmapped.arcaeon.verdict` and `unmapped.arcaeon.decision` are kept.
- Every profile name in `metadata.profiles` (the export applies none, so it stays `[]`); in particular the 1.9.0 Record Integrity profile (`attestation_list`).
- `ai_agent` inside `evidences` (1.9.0), and any other key the allowlist does not name.

`unmapped.arcaeon` is kept whole: `unmapped` is in the 1.3.0 class, as
OCSF's container for source-specific attributes.

What this mode does not do, and cannot prove:

- It writes JSON, one finding per call. Security Lake custom sources take Parquet (one OCSF class per source, time-sorted records, partitioned by region, account and day) delivered to the source's S3 location. arcaeon has no Parquet writer and no partitioning or delivery; that writer is not built.
- No vendor has been sent one of these events. The fixture tests (tests/fixtures/ocsf/, one 1.3.0 finding per verdict word) check the shape against what the vendors' pages and the 1.3.0 schema say: version at most 1.3, the required attributes present, only allowlisted keys; and for Datadog's path the version string, class_uid, category_uid, type_uid and the base attributes a mapping keys on. They were not run through AWS's OCSF validation tool, a Security Lake custom source, or a Datadog pipeline. Passing them does not show either vendor accepts the event.
- Datadog's library mappings are for named source formats; arcaeon is not one of them. Bringing this event in through Datadog would mean a custom mapping or plain log ingest, which is untested here.
