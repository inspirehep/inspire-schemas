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

from inspire_schemas import api, errors, utils
from jsonschema import ValidationError


def test_validate_raises_if_no_schema_key():
    with pytest.raises(errors.SchemaKeyNotFound):
        api.validate(data={})


@mock.patch('inspire_schemas.utils.LocalRefResolver')
@mock.patch('inspire_schemas.utils.load_schema')
@mock.patch('inspire_schemas.utils.jsonschema_validate')
def test_validate_ok_if_schema_key(mock_jsonschema_validate, mock_load_schema,
                                   mock_localrefresolver):
    mydata = {'$schema': 'The Castle Anthrax'}
    mock_load_schema.side_effect = lambda schema_name: schema_name

    utils.validate(mydata)

    mock_load_schema.assert_called_with(schema_name=mydata['$schema'])
    mock_jsonschema_validate.assert_called()


@mock.patch('inspire_schemas.utils.LocalRefResolver')
@mock.patch('inspire_schemas.utils.load_schema')
@mock.patch('inspire_schemas.utils.jsonschema_validate')
def test_validate_ok_if_schema_str(mock_jsonschema_validate,
                                   mock_load_schema, mock_localrefresolver):
    mydata = 'The Castle Anthrax'
    schema_name = 'Sir Galad'
    mock_load_schema.side_effect = lambda schema_name: schema_name

    utils.validate(data=mydata, schema=schema_name)

    mock_load_schema.assert_called_with(schema_name=schema_name)
    mock_jsonschema_validate.assert_called()


def test_validate_raises_if_invalid_data():
    data = {
        'foo': 'bar',
    }
    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'object',
        'properties': {
            'foo': {
                'type': 'integer'
            }
        }
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_partial_date():
    data = '2017-02'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'date',
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_date():
    data = '2017-42'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'date',
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_raises_on_invalid_date_time():
    data = '2017-42-12T12:34:56',

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'date-time',
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_valid_uri_reference():
    data = '/foo/bar'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'uri-reference',
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_uri_reference():
    data = '@[]'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'uri-reference',
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)


def test_validate_accepts_valid_orcid():
    data = '0000-0002-3151-4077'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'orcid',
    }

    utils.validate(data, schema)


def test_validate_raises_on_invalid_orcid():
    data = '0000-0012-1234-5647'

    schema = {
        '$schema': 'http://json-schema.org/schema#',
        'type': 'string',
        'format': 'orcid',
    }

    with pytest.raises(ValidationError):
        utils.validate(data, schema)
