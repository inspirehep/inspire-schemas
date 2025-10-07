# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016 CERN.
#
# INSPIRE-SCHEMAS is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# INSPIRE-SCHEMAS is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with INSPIRE-SCHEMAS; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

import mock
import pytest
from jsonschema import ValidationError

from inspire_schemas import api, errors, utils


def test_validate_raises_if_no_schema_key():
    with pytest.raises(errors.SchemaKeyNotFound):
        api.validate(data={})


@mock.patch("inspire_schemas.utils.LocalRefResolver")
@mock.patch("inspire_schemas.utils.load_schema")
@mock.patch("inspire_schemas.utils.jsonschema_validate")
def test_validate_ok_if_schema_key(
    mock_jsonschema_validate, mock_load_schema, mock_localrefresolver
):
    mydata = {"$schema": "The Castle Anthrax"}
    mock_load_schema.side_effect = lambda schema_name: schema_name

    utils.validate(mydata)

    mock_load_schema.assert_called_with(schema_name=mydata["$schema"])
    mock_jsonschema_validate.assert_called()


@mock.patch("inspire_schemas.utils.LocalRefResolver")
@mock.patch("inspire_schemas.utils.load_schema")
@mock.patch("inspire_schemas.utils.jsonschema_validate")
def test_validate_ok_if_schema_str(
    mock_jsonschema_validate, mock_load_schema, mock_localrefresolver
):
    mydata = "The Castle Anthrax"
    schema_name = "Sir Galad"
    mock_load_schema.side_effect = lambda schema_name: schema_name

    utils.validate(data=mydata, schema=schema_name)

    mock_load_schema.assert_called_with(schema_name=schema_name)
    mock_jsonschema_validate.assert_called()


def test_validate_raises_if_invalid_data():
    data = {
        "foo": "bar",
    }
    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "object",
        "properties": {"foo": {"type": "integer"}},
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_partial_date():
    data = "2017-02"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "date",
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_date():
    data = "2017-42"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "date",
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_raises_on_invalid_date_time():
    data = ("2017-42-12T12:34:56",)

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "date-time",
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_valid_uri_reference():
    data = "/foo/bar"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "uri-reference",
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_uri_reference():
    data = "@[]"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "uri-reference",
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_valid_orcid():
    data = "0000-0002-3151-4077"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "orcid",
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_orcid():
    data = "0000-0012-1234-5647"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "orcid",
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_valid_timezone():
    data = "Europe/Zurich"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "timezone",
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_timezone():
    data = "SevenKingdoms/KingsLanding"

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "string",
        "format": "timezone",
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_uniqueitems_detects_duplicate_scalars():
    data = [1, 2, 3, 2]

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "array",
        "uniqueItems": True,
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_uniqueitems_order_insensitive_for_objects_via_get_validation_errors():
    data = [{"a": 1, "b": 2}, {"b": 2, "a": 1}]

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "array",
        "items": {"type": "object"},
        "uniqueItems": True,
    }

    errors = list(utils.get_validation_errors(data, schema))
    assert len(errors) == 1
    assert "has non-unique elements" in errors[0].message


def test_get_validation_errors_empty_on_valid_input():
    data = [{"x": 1}, {"x": 2}, {"x": 3}]

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "array",
        "items": {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]},
        "uniqueItems": True,
    }

    errors = list(utils.get_validation_errors(data, schema))
    assert errors == []


def test_uniqueitems_nested_objects_duplicate_via_get_validation_errors():
    obj1 = {
        "id": 42,
        "meta": {
            "tags": ["a", "b", {"k": 1, "v": [1, 2, {"x": "y"}]}],
            "props": {
                "z": 3,
                "w": [{"p": 1}, {"q": 2}],
            },
        },
        "authors": [{"full_name": "Doe, J."}, {"full_name": "Roe, J."}],
        "record": {"$ref": "https://inspirebeta.net/api/literature/22490"},
    }

    obj2 = {
        "record": {"$ref": "https://inspirebeta.net/api/literature/22490"},
        "authors": [{"full_name": "Doe, J."}, {"full_name": "Roe, J."}],
        "meta": {
            "props": {
                "w": [{"p": 1}, {"q": 2}],
                "z": 3,
            },
            "tags": ["a", "b", {"v": [1, 2, {"x": "y"}], "k": 1}],
        },
        "id": 42,
    }

    data = [obj1, obj2]

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "array",
        "items": {"type": "object"},
        "uniqueItems": True,
    }

    errors = list(utils.get_validation_errors(data, schema))
    assert len(errors) == 1
    assert "has non-unique elements" in errors[0].message


def test_multiple_uniqueitems_errors_two_fields():
    data = {
        "a": [1, 2, 1],
        "b": [
            {"x": 1, "y": 2},
            {"y": 2, "x": 1},
        ],
    }

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "object",
        "additionalProperties": False,
        "required": ["a", "b"],
        "properties": {
            "a": {
                "type": "array",
                "items": {"type": "integer"},
                "uniqueItems": True,
            },
            "b": {
                "type": "array",
                "items": {"type": "object"},
                "uniqueItems": True,
            },
        },
    }

    errors = list(utils.get_validation_errors(data, schema))
    assert len(errors) == 2
    assert all("has non-unique elements" in e.message for e in errors)


def test_uniqueitems_detects_duplicates_with_validate():
    data = {
        "a": [1, 2, 1],
        "b": [
            {"x": 1, "y": 2},
            {"y": 2, "x": 1},
        ],
    }

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "object",
        "additionalProperties": False,
        "required": ["a", "b"],
        "properties": {
            "a": {
                "type": "array",
                "items": {"type": "integer"},
                "uniqueItems": True,
            },
            "b": {
                "type": "array",
                "items": {"type": "object"},
                "uniqueItems": True,
            },
        },
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_uniqueitems_passes():
    data = {
        "a": [1, 2],
        "b": [
            {"x": 1, "y": 2},
            {"y": 2, "x": 2},
        ],
    }

    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "type": "object",
        "additionalProperties": False,
        "required": ["a", "b"],
        "properties": {
            "a": {
                "type": "array",
                "items": {"type": "integer"},
                "uniqueItems": True,
            },
            "b": {
                "type": "array",
                "items": {"type": "object"},
                "uniqueItems": True,
            },
        },
    }
    utils.validate(data, schema)
