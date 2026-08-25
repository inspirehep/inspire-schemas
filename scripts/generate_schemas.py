"""Generate the resolved schemas and JavaScript country-code data."""

import json
import os
from pathlib import Path

import yaml

from inspire_schemas.utils import COUNTRY_CODE_TO_NAME

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = PROJECT_ROOT / "inspire_schemas" / "records"


def _resolve_json_schema(json_schema, path):
    if isinstance(json_schema, list):
        return [_resolve_json_schema(item, path) for item in json_schema]

    if isinstance(json_schema, dict):
        for key in json_schema:
            if key == "$ref" and not isinstance(json_schema[key], dict):
                subschema_path = Path(path, json_schema[key]).with_suffix(".yml")
                with subschema_path.open("rb") as yaml_file:
                    data = yaml.full_load(yaml_file.read())
                return _resolve_json_schema(data, Path(path, os.path.dirname(json_schema[key])))
            json_schema[key] = _resolve_json_schema(json_schema[key], path)

    return json_schema


def _yaml_to_json(yaml_file):
    with yaml_file.open("rb") as yaml_fd:
        data = yaml.full_load(yaml_fd.read())

    resolved_data = _resolve_json_schema(data, yaml_file.parent)
    with yaml_file.with_suffix(".json").open("w") as json_fd:
        json.dump(
            resolved_data,
            json_fd,
            indent=4,
            separators=(",", ": "),
            sort_keys=True,
        )
        json_fd.write("\n")


def _generate_country_code():
    data = {
        "maxLength": 2,
        "minLength": 2,
        "title": "ISO 3166-1 or 3166-3 alpha 2 country code",
        "type": "string",
        "enum": list(COUNTRY_CODE_TO_NAME),
    }

    with (SCHEMAS_DIR / "elements" / "country_code.yml").open("w") as yaml_fd:
        yaml.dump(data, yaml_fd)


def generate_json_schemas():
    _generate_country_code()
    for yaml_file in SCHEMAS_DIR.rglob("*.yml"):
        _yaml_to_json(yaml_file)


def generate_country_js_file():
    output_path = PROJECT_ROOT / "js" / "countryCodeToName.json"
    with output_path.open("w") as json_fd:
        json.dump(COUNTRY_CODE_TO_NAME, json_fd)


if __name__ == "__main__":
    generate_json_schemas()
    generate_country_js_file()
