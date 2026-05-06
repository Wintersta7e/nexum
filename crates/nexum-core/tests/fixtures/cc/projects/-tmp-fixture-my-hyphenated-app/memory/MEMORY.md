# my-hyphenated-app — memory index

This project's slug `-tmp-fixture-my-hyphenated-app` is **ambiguous**. It could
decode to:

- `/tmp/fixture/my-hyphenated-app` (1 inner hyphenated component, intended)
- `/tmp/fixture/my/hyphenated/app` (3 single-word components)
- `/tmp/fixture/my-hyphenated/app` (mixed)
- `/tmp/fixture/my/hyphenated-app` (mixed)

Slug-decoding caveat: the encoded slug is best-effort fallback only.
Project identity must prefer `git_origin_url` (when readable from the candidate
path's `.git/`) and the user-registered project name in
`~/.nexum/config.toml [projects.<name>]`. Tests should expect ambiguous-warn
behavior here, NOT silent commitment to one of the splits.

## Pointers

- [feedback_naming](feedback_naming.md) — slug-decode ambiguity is a real failure mode
