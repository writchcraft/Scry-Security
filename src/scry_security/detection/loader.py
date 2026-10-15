"""Constrained YAML loading: safe types, bounded files, no aliases or duplicate keys."""

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from scry_security.detection.rules import Rule


class RuleLoadError(ValueError):
    """Invalid rule catalogue; messages deliberately omit input contents."""


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in keys:
                raise RuleLoadError("YAML mappings require unique string keys")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def load_rules(path: Path | None = None) -> list[Rule]:
    source = (
        path if path is not None else files("scry_security").joinpath("rule_catalog/default.yaml")
    )
    try:
        with source.open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise RuleLoadError("Rule catalogue exceeds 1 MiB")
        text = raw.decode("utf-8")
        if any(
            isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
            for token in yaml.scan(text)
        ):
            raise RuleLoadError("YAML aliases and anchors are not supported")
        data = yaml.load(text, Loader=UniqueKeyLoader)
        if not isinstance(data, list) or not 1 <= len(data) <= 100:
            raise RuleLoadError("A catalogue must contain between 1 and 100 rules")
        rules = [Rule.model_validate(item) for item in data]
        if len({rule.rule_id for rule in rules}) != len(rules):
            raise RuleLoadError("Duplicate rule IDs")
        return rules
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, RecursionError) as exc:
        raise RuleLoadError("Cannot read or validate rule catalogue") from exc
