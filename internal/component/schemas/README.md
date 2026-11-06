# Prappser JSON Schemas

Language-neutral JSON Schemas (draft 2020-12) for the data a Prappser component stores and for the template document. The Dart app tests against them. The Go space server copies them byte for byte (prappser-spaces#78, santhosh-tekuri jsonschema v6) and uses them for the MCP `create_app` tool (#81).

## Layout

| File | `$id` |
|---|---|
| `component/<type>.v1.schema.json` (text, checklist, files, map, poll, chat, expenses, countdown) | `https://prappser.app/schemas/component/<type>.v1.schema.json` |
| `component/common.v1.schema.json` | shared `$defs` (Quill ops), not a component type |
| `template/template-doc.v1.schema.json` | `https://prappser.app/schemas/template/template-doc.v1.schema.json` |
| `vectors/<type>.json`, `vectors/template-doc.json` | test vectors, see below |
| `vectors/lens/<op>.json`, `vectors/lens/chain.json` | lens (`x-migrations`) test vectors, see Lens vectors |

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

- `gate`: members may write only when the flag's current value is not `false`. When the flag is absent, its schema `default` applies (every gate flag declares a boolean `default`). For object values `gate` is checked as described under `fields`: on a create, and for each changed field not listed in `fields`. Owner and admin bypass the gate.
- `fields`: the old and new values are compared field by field. A value that is absent, `''` or not an object counts as `{}`, and a field that is missing, `null`, `false`, `''` or `0` counts as unset. Each changed field is checked against `fields[field]` if listed (`null` means open), otherwise against `gate` (if the rule has none, the field is open). A tombstone (`''` over an object) counts every set field of the old value as changed. When the old value is not an object (a create, or a key holding `''`), `gate` applies too. Owner and admin bypass these checks.
- `unless`: the key is blocked for every role, owner and admin included, while the flag's current value is true. When the flag is absent, its schema `default` applies. There is no bypass.
- `append`: the key must not exist yet, and no tombstone. Applies to all roles.
- `author`: the decoded value's field must equal the caller's public key. When the key already exists, the old decoded value's field must too, so a tombstone or an edit of someone else's entry is rejected. Applies to all roles.
- `content`: a non-empty value must be a JSON string that decodes and validates against `<$id>#/$defs/<name>`. `''` is a tombstone and skips this check (`append` and `author` still apply).
- Per-member keys (`x-merge: per-member`) need nothing extra: for all roles the key must match the pattern with its trailing `.+$` replaced by the caller's quoted public key plus `$`.
- Viewers cannot write through MCP at all.
- `x-access` is an annotation for MCP writes. Validators ignore it. The app's own UI enforces its rules separately.

## Versioning

Data carries versions per entry. Readers migrate on read with lens ops declared in the schema. Old clients stay allowed and are never forced to update: they read newer data through the chain and, when they edit a newer entry, write back in that entry's own version. A newer client editing an older entry upgrades it (see Write-back). Unknown top-level keys and unknown fields inside entry values always survive an edit.

### Where migrations live

`<type>.vN.schema.json` (N >= 2) has a root keyword `x-migrations`: every step from 2 to N, in order. A vN file repeats the steps of v(N-1) unchanged and appends step N, so the newest file alone holds the whole chain. v1 files have none. Older files never change.

    "x-migrations": [
      { "to": 2, "breaking": false, "entries": { "^item_.+$": [ { "op": "rename", "from": "done", "to": "checked" } ] } }
    ]

- `to`, `breaking` (boolean) and `entries` are required. `to` runs 2, 3, ... N with no gap. The file's `$id` version equals the last `to`.
- `entries` keys are `patternProperties` keys of the same file, verbatim, whose `x-merge` is `per-entry`. A family not listed has no ops in that step; its entries still get the new `v`.
- Ops in a list apply in order, each seeing the result of the one before.
- A field name is never reused in a family: a name a previous version declared is not given a different meaning later.
- `entries` keys are JSON Schema `pattern` regexes (ECMA 262 subset, as for `patternProperties`), matched unanchored as JSON Schema does, so keys carry their own `^` and `$`.
- `breaking: true` marks a step that readers older than the step cannot work with (see Component state). A step with `breaking: true` and empty `entries` is a valid marker.

### Walking the chain

To migrate a value stored under `key` to version T:

1. e = the value's `v`, 1 when absent. A `v` that is not a number with an integer value >= 1 is `bad-version`: the entry is kept untouched, not shown, ignored for state, and never written back or tombstoned by a lens path.
2. e = T: unchanged, including an absent `v`, which stays absent.
3. e < T: for k = e+1 .. T, apply the up direction of step k's ops.
4. e > T: for k = e down to T+1, apply the down direction of step k's ops: the ops in reverse order, each inverted. If step k has `breaking: true`, stop with `breaking`.
5. A needed step that is not known is `missing-step`. A crossed step or op with an unknown op name, an unknown member, or arguments that break a rule below is `unsupported`. Only steps the walk crosses and only the ops list of this key's family are checked; a step that is not crossed is never validated.
6. When e differs from T, set `v` to T in the result, explicitly, even for T = 1.

Step k's ops for `key`: the `entries` list whose key, used as a regex, matches `key`; none matches: no ops; more than one: `unsupported`.

Steps are processed in walk order and the first error wins. Within a step the order is: `missing-step` (the step is not known), then `unsupported`, then `breaking`.

### Paths

A path is dotted names, each matching `^[A-Za-z_][A-Za-z0-9_]*$`. There is no array indexing: arrays and scalars are leaves. The first name is never `v`. An empty path, an empty name (`a..b`), a name that does not match the regex, a first name `v` or an index segment such as `a.0` is `unsupported`. Absent and JSON `null` differ.

- get: absent when a name is missing or a parent is not an object.
- remove: no-op when absent. After removing, each ancestor left as an empty object is removed too, deepest first, never the root. Only an ancestor emptied by the removal is pruned; an empty object elsewhere is an ordinary value.
- set (inside an op): missing parents are created as `{}`. If a parent exists and is not an object, the op is a no-op.

### Ops

Ops are declared in the up direction. Every precondition is checked on the input, before the op changes anything. Every op leaves every field it does not name untouched, at every depth, including unknown fields and the siblings of a moved or wrapped field.

| Op | Up | Down |
|---|---|---|
| `rename {from, to}` | single names only, otherwise as `move` | as `move` |
| `move {from, to}` | `from` absent or `to` unsettable: no-op. Else read `from`, remove `from`, set `to` (an existing `to` is replaced). | the same with `from` and `to` swapped |
| `add {path, default}` | `path` absent: set a deep copy of `default`. Present, null included: untouched. | remove `path` |
| `map {path, pairs, fallback?}` | value equal to an old value: its new value. Otherwise unchanged. | value equal to a new value: its old value. Otherwise `fallback` when declared, else unchanged. |
| `wrap {path}` | `null` -> `[]`, array unchanged, any other value -> `[value]` | `[]` -> `null`, `[x, ...]` -> `x`, non-array unchanged |
| `unwrap {path}` | as `wrap` down | as `wrap` up |

Absent path: every op is a no-op, except `add` up, which sets the default.

Declaration rules (else `unsupported`): every op is an object with a known `op` name and exactly its members: `rename` and `move` need `from` and `to`, `add` needs `path` and `default`, `map` needs `path` and `pairs` and may carry `fallback`, `wrap` and `unwrap` need `path`; a missing required member is `unsupported`. Every path obeys the Paths rules. `default` may be any JSON value. `fallback` is a string, number, boolean or null. `move` and `rename` paths are not equal (so `rename` with `from` equal to `to` is `unsupported`) and neither is a prefix of the other (by names). `pairs` is a list of 2-element lists `[old, new]`; each item is a string, number, boolean or null; old values are unique and new values are unique. `fallback` counts as declared when the member is present, even when its value is null. Matching is one lookup by JSON equality: no chaining, no type coercion (`1` is not `"1"`), numbers compare by value.

Authoring rules (checked against the schema, not by interpreters): with `fallback`, `pairs` lists every old value (identity pairs allowed) and `fallback` is a valid old value. A new value that is also a valid old value must be listed as an old value too. When the new version allows a value with no old counterpart, declare `fallback`.

### What loses data

| Op | Lossy up | Lossy down |
|---|---|---|
| `map` with `fallback` | no | yes |
| `wrap` | no | yes |
| `unwrap` | yes | no |
| all others | no | no |

Lossiness is decided statically from the ops the traversal crosses, never from the value: an entry whose field holds `["a"]` is still lossy through `wrap` down, and read-only. A traversal is lossy when it crosses an op that is lossy in a direction the client uses. A client reading an entry newer than itself (e > R) uses both directions (down to read, up to write back). A client reading an older entry (e < R) uses up only, because it writes in its own version. e = R is never lossy. An entry with a lossy traversal is read-only.

### `v` per key family

Absent `v` means 1 everywhere. A writer at version 2 or above always writes `v`.

- Object entries (`item_<id>`): `value.v`.
- Encoded entries (`m_`, `e_`, `s_`: `type: string` with `contentMediaType: application/json`): `v` on the decoded object. Decode, migrate or write back, encode. The bytes of the encoding are not part of the contract; compare decoded values.
- Tombstones (`''`, `null`) and values that do not decode to an object are not entries: passed through untouched.
- Per-member cells (`vote_<pk>`, `react_<msgKey>_<pk>`) and settings keys (every top-level property, including single-key aggregates such as poll `options`, map `markers`, checklist `templates`, text `document`) have no `v` and are never migrated.
- The top-level `v` of chat, poll, expenses and countdown is the settings format. It stays `const 1` in every vN file and readers do not use it to pick a chain.
- In a vN file every entry `$defs` requires `v` with `const N`. v1 entry definitions accept an optional `v: 1`.
- An entry is validated against the schema file of its own version: `v` absent is the v1 file, `v` = N is the vN file, so `additionalProperties: false` and the `const N` on `v` apply per version. A validator that holds only its own newest file (the app) migrates the entry to its version first, then validates the result. The space embeds every version from min on and validates in the entry's own version. A written value is validated in the version it carries: R for a new entry and for an e < R write, e for an e > R write-back.

### Write-back

Let O be the stored value at save time (version e), R the writer's version, V = migrate(O, R) the view and V' the edited view. V' is produced by patching the view JSON, never by re-encoding a typed model, in both branches below, so unknown fields carried through V survive. Write-back works on the stored JSON.

- e > R (an older client edits a newer entry; this is the "write back in the entry's own version" rule): U = migrate(V, e), U' = migrate(V', e). Diff U against U' (rules below) and apply the changes to O. `v` is never diffed: O keeps its `v`. Fields the writer does not know (unknown fields, fields hidden by `add`) are equal in U and U' and stay untouched.
- e = R: the same diff rule applies with U = V and U' = V'; O keeps its `v` (absent stays absent).
- e < R (a newer client edits an older entry): upgrade on edit. Write V' as is, with `v` = R. Writing in e would drop edits to fields e lacks. The rule that an entry is written back in its own version binds only the e > R case.
- The `v` of the edited view V' is never read: in the e >= R branch U' = migrate(V' with `v` set to R, e); in the e < R branch V' and V are compared ignoring `v`, and the written value gets `v` = R.
- An entry whose migration to R fails (it is `needs-update`) cannot be edited and returns that migrate error. This takes precedence over `read-only`.
- A read-only entry is not written: `read-only`. `read-only` is decided before any diff: a lossy entry is `read-only` even when the edit changes nothing. A `bad-version` entry is never written and never tombstoned by a lens path.
- No write when the result deep-equals O (e >= R) or when V' deep-equals V (e < R).
- A new entry is written in R. Deleting an entry writes the tombstone and needs no lens.
- Diff, per top-level member of U and U' except `v`: both objects: recurse. Deep equal (both absent counts): nothing. Absent in U': delete that member from O. No ancestor is pruned: the diff only recurses into objects present in both, so every ancestor exists in U' and an explicit `{}` in the edited view survives. Otherwise: set that path in O to a deep copy of the U' value; here missing parents are created and a parent that is not an object is replaced by `{}`.
- Deep equality: same type, objects with equal key sets and equal values, arrays element by element, numbers by value.
- An access check that compares an old and a new value (`x-access` `fields`) first migrates the old value to the new value's version; if that migration fails, the write is rejected with that migrate error. An MCP write of an existing entry follows the same write-back rule, with the space's current version as R.

### Last writer wins across versions

The top-level key stays the unit of merge in every version. When two clients on different versions write the same key, the later write replaces the whole value, exactly as between two clients on one version. Each writer's value is consistent in its own `v`, and readers migrate it. A client that read the entry at v1 before another client upgraded it to v3 writes v1 back: the v3 edit is lost like any concurrent edit, and readers lift the v1 value up again.

### Settings keys and per-member cells

Settings keys and per-member cells change additively only: a new optional key, or a new optional field in a value, whose absence means its default. Renaming, retyping or remapping them, or a key-family prefix, is not expressible. Under per-key last writer wins an old client keeps writing the old key, nothing orders the old key against the new one, and readers disagree about which is current. Keeping the old key read-only and deprecated (as `items` was) shadows old clients' later writes, so it is not a safe pattern while old clients are allowed. Such a change needs a new component type. Text, map, files and countdown have no entries, so they can only change additively.

### Component state

For a reader at version R with chain known up to K, each entry (tombstones and `bad-version` skipped) gets:

| State | When |
|---|---|
| `needs-update` | migrating to R fails with `missing-step`, `unsupported` or `breaking` |
| `read-only` | the traversal is lossy |
| `full` | otherwise |

The component takes the worst state of its entries (`needs-update` > `read-only` > `full`). No entries: `full`. `breaking` only stops readers older than the step: it is an error on a down traversal and harmless going up.

### Bundle manifest

A schema bundle is described by `bundle.json`, the unit slice 5 signs:

    {
      "bundle": 12,
      "types": {
        "Checklist": { "min": 1, "current": 3 }
      },
      "files": [
        { "path": "component/checklist.v1.schema.json", "sha256": "<64 lowercase hex>" }
      ]
    }

- `bundle`: integer >= 1, strictly increasing over releases. A consumer never replaces a bundle with one whose number is not greater.
- `types`: every component type, keyed by the exact `type` string stored in component rows (the `name` column of `ComponentEntity`, set from `ComponentDef.name`): `Text`, `Checklist`, `Files`, `Map`, `Chat`, `Poll`, `Expenses`, `Countdown`. `min <= current`. The bundle ships files v`min` through v`current`. The chain inside the current file still starts at v1, so raising `min` never makes stored data unreadable. The schema file stem is the lowercase of the type string.
- `files`: every shipped schema file: each component file from `min` to `current`, `component/common.v1.schema.json`, `template/template-doc.v1.schema.json`. Paths are relative to `schemas/`, unique, sorted by byte order. `sha256` is over the raw file bytes. README and vectors are not shipped.
- Unknown members are ignored. Signature, key id and container format belong to slice 5. The app embeds only the current version of each type; the space image embeds every version from `min` (min is 1 for now, bumped by the owner via the manifest).

### Not yet enforced

Nothing checks `x-migrations` yet, because no schema has one. Slice 8 (the first real v2) must add: tripwires for the cumulative prefix, contiguous `to`, `$id` version equal to the last `to`, `entries` keys being per-entry patterns, and the `map` authoring rules; and fix the `.v1` filename assumptions (the Go loader's `strings.TrimSuffix(path.Base(file), ".v1.schema.json")` in `newValidator`, the Dart tripwire's `replaceFirst('.v1.schema.json', '')`, `componentSchemaId` hard-coding `.v1`, and both coverage tests requiring a top-level vector file per schema id). Lens vectors in `vectors/lens/` are not read by the existing runners; slices 3a (Dart) and 3b (Go) add runners.

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

### Lens vectors

`vectors/lens/<op>.json` (`rename`, `move`, `add`, `map`, `wrap`, `unwrap`) and `vectors/lens/chain.json` hold `{ "cases": [ ... ] }`. They test the walk, the ops, the lossiness rules, write-back and component state defined under Versioning. The runners for `vectors/<name>.json` list `vectors/` without recursing, so they do not read `vectors/lens/`; lens runners are separate. A case carries `steps` in the exact `x-migrations` shape, spelled out in full, and uses the `key` `item_a` against the family `^item_.+$` unless the case tests family matching. Encoded families are not used: vectors carry decoded values. Values compare by deep equality (member order ignored, numbers by value). Like the other vectors, they contain no integral floats such as `1.0`. An optional `note` string is allowed on any case.

| Kind | Members | Meaning |
|---|---|---|
| `migrate` | `name`, `kind`, `steps`, `key`, `in`, `to`, plus (`out` and `lossy`) or `error` | `out` = migrate(`in`, `to`). `lossy` = the static classification of the traversal from `in.v` to `to`, with `to` as the reader. `error` is one of `bad-version`, `missing-step`, `unsupported`, `breaking`. |
| `writeback` | `name`, `kind`, `steps`, `key`, `original`, `reader`, `view`, `edited`, plus `result` or `error` | `view` = migrate(`original`, `reader`). `edited` = the edited view V'. `result` = the stored value after write-back. `error` is a migrate error or `read-only`. |
| `state` | `name`, `kind`, `steps`, `reader`, `entries`, `expect` | `entries` = `[{key, value}]` of decoded values (tombstones and bad `v` allowed). `expect` is `full`, `read-only` or `needs-update`. K = the last `to` in `steps`. |

Example, a migrate case:

```json
{
  "name": "wrap down keeps the first element",
  "kind": "migrate",
  "steps": [
    {
      "to": 2,
      "breaking": false,
      "entries": {
        "^item_.+$": [
          { "op": "rename", "from": "tag", "to": "tags" },
          { "op": "wrap", "path": "tags" }
        ]
      }
    }
  ],
  "key": "item_a",
  "in": { "v": 2, "title": "Milk", "tags": ["a", "b"] },
  "to": 1,
  "out": { "v": 1, "title": "Milk", "tag": "a" },
  "lossy": true
}
```

Example, a write-back case. A v1 client unchecks a v3 entry; the hidden `assignee` survives. Steps are `[{to 2: rename done to checked}, {to 3: move due to when.date, add assignee with default null}]`. U = migrate(view, 3) has `checked` true and U' = migrate(edited, 3) has `checked` false; only `checked` differs, so `assignee` and `v` survive.

```json
{
  "name": "v1 client unchecks a v3 entry, assignee survives",
  "kind": "writeback",
  "steps": [
    {
      "to": 2,
      "breaking": false,
      "entries": { "^item_.+$": [ { "op": "rename", "from": "done", "to": "checked" } ] }
    },
    {
      "to": 3,
      "breaking": false,
      "entries": {
        "^item_.+$": [
          { "op": "move", "from": "due", "to": "when.date" },
          { "op": "add", "path": "assignee", "default": null }
        ]
      }
    }
  ],
  "key": "item_a",
  "original": { "v": 3, "text": "Mleko", "checked": true, "when": { "date": "2026-11-08" }, "assignee": "bartek" },
  "reader": 1,
  "view": { "v": 1, "text": "Mleko", "done": true, "due": "2026-11-08" },
  "edited": { "v": 1, "text": "Mleko", "done": false, "due": "2026-11-08" },
  "result": { "v": 3, "text": "Mleko", "checked": false, "when": { "date": "2026-11-08" }, "assignee": "bartek" }
}
```

## Not expressible in a schema

The consumer enforces these, they are not checked here:

- Byte limits: a template file is at most 256 KiB and the template document at most 64 KiB.
- The chat body (4000) and checklist title (1000) `maxLength` count code points while the app counts UTF-16 units, so for astral characters the schema is up to 2x looser. ponytail: ceiling is 2x the limit for astral characters; add a UTF-16 length check in the MCP tool if it matters.
- A member can uncheck a legacy checklist item that lives only in `items` while `allowToggleInUsage` is false. The old value is read from `item_<id>` only, so a write of `item_<id>` with `checked: false` is compared against `{}` and `checked` counts as unchanged. It still needs `allowAddInUsage`.
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
