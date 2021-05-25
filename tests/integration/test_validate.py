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

import json
import os

import jsonschema
import pytest
import six

from datetime import datetime
from inspire_schemas import api

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), 'fixtures')

    

def get_schema_names(fixtures_path):
    schema_names = []
    _, _, files = six.next(os.walk(fixtures_path))
    schema_names.extend(
        file_name.split('_', 1)[0]
        for file_name in files
        if file_name.endswith('.json')
    )

    return schema_names


def load_example(schema_name):
    example_path = os.path.join(FIXTURES_PATH, schema_name + '_example.json')
    with open(example_path) as example_fd:
        data = json.loads(example_fd.read())

    return data


def change_something(data):
    for key, elem in data.items():
        if isinstance(elem, int):
            data[key] = (
                "Look, I'm a knight, I'm supposed to get as much peril as I"
                " can."
            )
        else:
            data[key] = 42
        break
    else:
        raise Exception('Unable to change anythng on data "%s"' % data)

    return data


@pytest.mark.parametrize(
    'schema_name',
    get_schema_names(FIXTURES_PATH),
    ids=get_schema_names(FIXTURES_PATH),
)
def test_schemas_validate(schema_name):
    example_data = load_example(schema_name)
    api.validate(data=example_data, schema=schema_name)


@pytest.mark.parametrize(
    'schema_name',
    get_schema_names(FIXTURES_PATH),
    ids=get_schema_names(FIXTURES_PATH),
)
def test_schemas_validate_negative(schema_name):
    example_data = load_example(schema_name)
    example_data = change_something(example_data)
    with pytest.raises(jsonschema.ValidationError):
        api.validate(data=example_data, schema=schema_name)


def test_date_validation(date_text):
    example_data = load_example("authors")
    example_data['birth_date'] = "4.12.1979"
    with pytest.raises(ValueError):
        api.validate(schema=date_text, data=example_data)

