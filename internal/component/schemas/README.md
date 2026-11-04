# Prappser JSON Schemas

Language-neutral JSON Schemas (draft 2020-12) for the data a Prappser component stores and for the template document. The Dart app tests against them. The Go space server copies them byte for byte (prappser-spaces#78, santhosh-tekuri jsonschema v6) and uses them for the MCP `create_app` tool (#81).

## Layout

| File | `$id` |
|---|---|
| `component/<type>.v1.schema.json` (text, checklist, files, map, poll, chat, expenses, countdown) | `https://prappser.app/schemas/component/<type>.v1.schema.json` |
| `component/common.v1.schema.json` | shared `$defs` (Quill ops), not a component type |
| `template/template-doc.v1.schema.json` | `https://prappser.app/schemas/template/template-doc.v1.schema.json` |
| `vectors/<type>.json`, `vectors/template-doc.json` | test vectors, see below |

Files refer to each other with `$ref` to the absolute `$id`. A consumer must register every file under its `$id` before compiling and must not fetch anything over the network.

The template-doc schema validates the `template` object of a `prappser.template` file (name, description, icon, groups), not the outer envelope. Each component's `data` is dispatched on `type` to the component schema. Template `data` may not contain keys starting with `m_`, `react_`, `vote_`, `e_` or `s_`, so a template cannot carry messages, reactions, votes or expenses in another member's name.

## What a schema describes

A schema describes the `data` map of one component as it is stored and synced. Component data is a flat JSON object whose top-level keys are the unit of sync.

Rules that hold for every schema:

- `additionalProperties: false` wherever we own the shape. The exceptions are top-level keys starting with `_` (layout keys, any value), the `attributes` of a Quill op (open), and legacy keys kept so old rows still validate.
- Required fields equal what the Dart `fromJson` requires. Fields with a Dart default are optional.
- Unknown keys are rejected here even though the Dart decoders ignore them.

The schemas are stricter than the app's decoders on purpose. They are the contract for what we write and what we accept from outside (MCP, templates), and the strictness makes Dart and Go drift show up as a failing test. The decoders stay tolerant so a newer client does not break an older one. Today the space server validates only MCP writes (`create_app` and the checklist tools) against these files. The app and event ingestion do not validate, so a limit does not reject data already stored or synced, but it can make an MCP write fail. The app's checklist title field has no 1000 cap, so an existing longer title makes an agent write of that item (for example a toggle) fail validation. Anything that validates the event path later has to decide for itself whether this strictness fits.

## Sync model and `x-merge`

Every top-level `properties` entry and every `patternProperties` entry carries an `x-merge` annotation. It documents how two writers are reconciled, per top-level key:

| Value | Meaning |
|---|---|
| `single` | One value for the whole key. Last writer wins. |
| `per-entry` | The key family holds independent entries (`m_<uuid>`, `e_<uuid>`, `s_<uuid>`). Each key is its own last-writer-wins cell. |
| `per-member` | The key family holds one cell per member (`vote_<publicKey>`, `react_<messageKey>_<publicKey>`). A member only writes their own cells. |

Decisions behind this (#270):

- One JSON Schema per component type, plus one for the template document.
- The unit of merge is the top-level key. There is no hybrid logical clock and no field-level merge inside a value.
- Rich text (`document`, checklist `detailsDocument`) is a single value. Concurrent edits are last writer wins, not merged.
- Checklist items are `item_<id>` keys (`per-entry`), the value omits the id. The old whole-list `items` key is deprecated (`"deprecated": true`, `single`): clients still read it as a read-only base and never write it. Templates may not carry `items`.
- Keys are never deleted by sync. A removed entry is a tombstone: `''` for string cells, `null` for countdown `customColor`. Schemas accept the tombstone.
- `x-merge` is an annotation. Validators ignore it. A tripwire test checks that none is missing and that the chat, poll and expenses key families keep their mode. It covers `x-access` the same way.

## Write access and `x-access`

Every top-level `properties` entry and every `patternProperties` entry carries an `x-access` annotation. It says who may write the key through MCP:

| Value | Meaning |
|---|---|
| `manage` | Owner and admin only. |
| `member` | Any member that is not a viewer. |
| `none` | Nobody through MCP (read-only or app-managed). |
| object | Member level plus the checks below. Any of the keys that follow. |
| `gate` | Name of a boolean property of the same schema. |
| `fields` | Map of inner field name to a boolean property name, or `null` for open. |
| `append` | `true`: the key may only be created. |
| `author` | Name of a field inside the decoded value that holds the writer's public key. |
| `content` | Name of a `$defs` entry the decoded value must satisfy. |
| `unless` | Name of a boolean property of the same schema. The key is blocked while it is true. |

Rules:

- `gate`: members may write only when the flag's current value is not `false`. When the flag is absent, its schema `default` applies (every gate flag declares a boolean `default`). Owner and admin bypass the gate.
- `fields`: when the old and new values are both objects, each changed inner field is checked against `fields[field]` if listed (`null` means open), otherwise against `gate`. Creates, tombstones and non-object values use `gate`.
- `unless`: the key is blocked for every role, owner and admin included, while the flag's current value is true. When the flag is absent, its schema `default` applies. There is no bypass.
- `append`: the key must not exist yet, and no tombstone. Applies to all roles.
- `author`: the decoded value's field must equal the caller's public key. When the key already exists, the old decoded value's field must too, so a tombstone or an edit of someone else's entry is rejected. Applies to all roles.
- `content`: a non-empty value must be a JSON string that decodes and validates against `<$id>#/$defs/<name>`. `''` is a tombstone and skips this check (`append` and `author` still apply).
- Per-member keys (`x-merge: per-member`) need nothing extra: for all roles the key must match the pattern with its trailing `.+$` replaced by the caller's quoted public key plus `$`.
- Viewers cannot write through MCP at all.
- `x-access` is an annotation for MCP writes. Validators ignore it. The app's own UI enforces its rules separately.

## Versioning

- The version is in the file name and the `$id` (`.v1`), and in the data key `v`.
- `v` is `const 1` and optional on Chat, Poll, Expenses and Countdown, which write it. Absent means 1. Text, Checklist, Files and Map have no `v` yet.
- Adding an optional field stays in v1: the schema changes in the same PR as the code. A change old readers cannot read, or that changes the meaning of a field, gets a `v2` file with a new `$id` and `v: 2` in the data. The v1 file stays.
- Encoded messages carry their own `v` (chat message, `$defs/message`).

## Portability

Only a portable keyword subset is used: no `format`, no `$dynamicRef`, no `unevaluatedProperties` or `unevaluatedItems`, no `prefixItems`. Regexes are anchored and valid in both RE2 and ECMAScript.

`contentSchema` is not used. The Dart `json_schema` package fails to compile an object-valued `contentSchema`, and the Go side would not enforce it by default either. The encoded values (chat `m_`, expenses `e_` and `s_`) are strings with `contentMediaType: application/json` as an annotation, and the decoded object is described under `$defs` (`message`, `expense`, `settlement`). A consumer that wants to check an inner value validates the decoded JSON against `<component $id>#/$defs/<name>`. The vectors do exactly that with a per-case `schema` override.

`maxLength` counts code points in JSON Schema. The app counts UTF-16 units (`String.length`), so the template name (64) and description (280) limits differ from the app only for non-BMP characters at the boundary.

## Vectors

`vectors/<name>.json` holds `{ "schema": "<$id or $id#/$defs/x>", "cases": [ ... ] }`. A case is:

```json
{ "name": "human readable", "schema": "optional override", "data": {}, "valid": true }
```

A consumer validates `data` against `schema` (the case override if present) and expects `valid`. Vectors contain no integral floats such as `1.0`, so Go and Dart decode them identically. `jsonDecode(jsonEncode(v))` keeps `4.0` as a double on the Dart VM but dart2js emits `4`, so integer-vs-number checks must not depend on it. Files are pretty-printed with a 2 space indent and a trailing newline.

## Not expressible in a schema

The consumer enforces these, they are not checked here:

- Byte limits: a template file is at most 256 KiB and the template document at most 64 KiB.
- The chat body (4000) and checklist title (1000) `maxLength` count code points while the app counts UTF-16 units, so for astral characters the schema is up to 2x looser. ponytail: ceiling is 2x the limit for astral characters; add a UTF-16 length check in the MCP tool if it matters.
- A member can create a checklist item with `checked: true` while `allowToggleInUsage` is false, because creates are checked against `gate` only.
- Chat reaction at most 32 UTF-16 units, checked by the app's controller and decoders.
- Checklist `attachmentIds`, chat attachment ids and Files `storageId` pointing at something that exists.
- Member references in a template: Map marker `createdBy` and `createdAtMs` and checklist `assignedMemberId` (and `attachmentIds`) let a template name a member or file. The schema allows them, so `create_app` must strip or reject them. The app's own template strip already clears them on export and import (Map `stripForTemplate` sets `createdBy` to `''`, `createdAtMs` to 0 and drops `otherUsers`; the checklist strip clears `assignedMemberId`, `attachmentIds` and `checked`).
- Calendar validity of a checklist `date` (`2026-02-30` matches the pattern).
- Settlement `from != to`, and that a vote names an existing option.
- That an encoded `m_`, `e_` or `s_` value is valid JSON of the right shape (see Portability).
- The `storage:` icon rewrite. The schema allows built-in icon names only. The app decoder turns a `storage:` icon into `quiz` instead of rejecting it.

## Changing a schema

1. Edit the schema and add or adjust vectors in the same change. Every new rule needs a valid and an invalid case.
2. Run `flutter test test/schemas`. It covers the vectors, payloads from the real write paths, the built-in templates, and the tripwires (type registry, `x-merge`, `x-access`, icon list).
3. Copy the files to prappser-spaces unchanged.
