# Detection catalogues

The authoritative default YAML catalogue is packaged at
`src/scry_security/rule_catalog/default.yaml`. Packaging it ensures installed
commands work outside a repository checkout. Do not maintain a second copy here.

Custom catalogues can live in this directory and be selected with `--rules`.
See `docs/detection_logic.md` for the schema, safe loading, tuning and tests.
