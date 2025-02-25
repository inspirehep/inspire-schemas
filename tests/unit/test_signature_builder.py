# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2014-2017 CERN.
#
# INSPIRE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# INSPIRE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with INSPIRE. If not, see <http://www.gnu.org/licenses/>.
#
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as an Intergovernmental Organization
# or submit itself to any jurisdiction.

from __future__ import absolute_import, division, print_function

import pytest
import inspect
import sys

from inspire_schemas.utils import load_schema, validate
from inspire_schemas.builders.signatures import SignatureBuilder
from jsonschema import ValidationError


@pytest.fixture(scope='module')
def subschema():
    schema = load_schema('hep')
    return schema['properties']['authors']['items']


def assert_field_valid(expected, result, property, schema):
    assert expected == result
    assert validate(
        result[property],
        schema['properties'][property]
    ) is None


def assert_field_invalid(expected, result, property, schema):
    assert expected == result
    with pytest.raises(ValidationError):
        assert validate(result[property], schema["properties"][property])


def test_ensure_fields():
    expected = {'created': 'new', 'existing': 'old'}

    builder = SignatureBuilder({'existing': 'old'})
    builder._ensure_field('created', 'new')
    builder._ensure_field('existing', 'new')
    result = builder.obj

    assert expected == result


def test_ensure_list_field():
    expected = {'created': ['new'], 'existing': ['old', 'new']}

    builder = SignatureBuilder({'existing': ['old']})
    builder._ensure_list_field('created', 'new')
    builder._ensure_list_field('existing', 'new')
    result = builder.obj

    assert expected == result


def test_signature_builder(subschema):
    expected = {
        'full_name': 'Smith, John',
    }

    builder = SignatureBuilder()
    builder.set_full_name('Smith, John')
    result = builder.obj

    assert expected == result
    assert validate(result, subschema) is None


def test_signature_builder_existing_author(subschema):
    existing = {
        'full_name': 'Smith, John',
    }
    expected = {
        'full_name': 'Smith, John',
        'emails': [
            'johnsmith@example.org',
        ],
        'ids': [
            {
                'value': '0000-0003-2635-0212',
                'schema': 'ORCID',
            },
        ],
    }

    builder = SignatureBuilder(existing)
    builder.add_email('johnsmith@example.org')
    builder.set_uid('0000-0003-2635-0212')
    result = builder.obj

    assert expected == result
    assert result is existing
    assert validate(result, subschema) is None


def test_add_affiliation(subschema):
    expected = {
        'affiliations': [
            {
                'value': 'Institution',
                'curated_relation': True,
                'record': {
                    '$ref': 'http://reference/api/institutions/123'
                },
            },
        ],
    }

    builder = SignatureBuilder()
    builder.add_affiliation('Institution', True, {'$ref': 'http://reference/api/institutions/123'})

    assert_field_valid(expected, builder.obj, 'affiliations', subschema)


def test_add_alternative_name(subschema):
    expected = {
        'alternative_names': [
            u'Petrovich Sidorov, Ivan',
            u'Петрович Сидоров, Иван',
        ]
    }

    builder = SignatureBuilder()
    builder.add_alternative_name(u'Petrovich Sidorov, Ivan')
    builder.add_alternative_name(u'Петрович Сидоров, Иван')

    assert_field_valid(expected, builder.obj, 'alternative_names', subschema)


def test_add_credit_role(subschema):
    expected = {'credit_roles': ['Conceptualization', 'Software']}

    builder = SignatureBuilder()
    builder.add_credit_role('Conceptualization')
    builder.add_credit_role('Software')

    assert_field_valid(expected, builder.obj, 'credit_roles', subschema)


def test_curate(subschema):
    expected = {'curated_relation': True}

    builder = SignatureBuilder()
    builder.curate()

    assert_field_valid(expected, builder.obj, 'curated_relation', subschema)


def test_add_email(subschema):
    expected = {
        'emails': [
            'someone@example.com',
            'someoneelse@example.org',
        ]
    }

    builder = SignatureBuilder()
    builder.add_email('someone@example.com')
    builder.add_email('someoneelse@example.org')

    assert_field_valid(expected, builder.obj, 'emails', subschema)


def test_set_full_name(subschema):
    expected = {'full_name': 'Carberry, Josiah'}

    builder = SignatureBuilder()
    builder.set_full_name('Josiah Carberry')

    assert_field_valid(expected, builder.obj, 'full_name', subschema)


def test_set_uid(subschema):
    expected = {
        'ids': [
            {
                'value': 'Josiah.Stinkney.Carberry.1',
                'schema': 'INSPIRE BAI',
            },
            {
                'value': '0000-0002-1825-0097',
                'schema': 'ORCID',
            },
            {
                'value': 'INSPIRE-12345678',
                'schema': 'INSPIRE ID',
            },
        ],
    }

    builder = SignatureBuilder()
    builder.set_uid('Josiah.Stinkney.Carberry.1')
    builder.set_uid('0000-0003-2635-0212')
    builder.set_uid('0000-0002-1825-0097')  # expect overwrite
    builder.set_uid('INSPIRE-12345678')

    assert_field_valid(expected, builder.obj, 'ids', subschema)


def test_set_uid_with_unknown_schema(subschema):
    expected = {"ids": [{"value": "Frank-Castle", "schema": "a-random-schema"}]}

    builder = SignatureBuilder()
    builder.set_uid("Frank-Castle", schema="a-random-schema")

    assert_field_invalid(expected, builder.obj, "ids", subschema)


def test_add_inspire_role(subschema):
    expected = {'inspire_roles': ['supervisor', 'editor']}

    builder = SignatureBuilder()
    builder.add_inspire_role('supervisor')
    builder.add_inspire_role('editor')

    assert_field_valid(expected, builder.obj, 'inspire_roles', subschema)


def test_add_raw_affiliation(subschema):
    expected = {
        'raw_affiliations': [
            {
                'value': 'Josiah Carberry',
                'source': 'source',
            },
        ],
    }

    builder = SignatureBuilder()
    builder.add_raw_affiliation('Josiah Carberry', 'source')

    assert_field_valid(expected, builder.obj, 'raw_affiliations', subschema)


def test_add_raw_affiliation_ror_detection(subschema):
    expected = {
        'affiliations_identifiers': [
            {
                'value': 'https://ror.org/02bfwt286',
                'schema': 'ROR',
            },
        ],
        'raw_affiliations': [
            {
                'value': 'Josiah Carberry',
                'source': 'source',
            },
        ],
    }
    builder = SignatureBuilder()
    builder.add_raw_affiliation('Josiah https://ror.org/02bfwt286Carberry', 'source')
    assert expected == builder.obj
    assert validate(builder.obj['affiliations_identifiers'],
                    subschema['properties']['affiliations_identifiers']) is None
    assert validate(builder.obj['raw_affiliations'],
                    subschema['properties']['raw_affiliations']) is None


@pytest.mark.skipif(sys.version_info < (3, 3), reason="`inspect.signature` requires python 3")
@pytest.mark.parametrize('field_name', dir(SignatureBuilder))
def test_public_method_ignores_none_params(field_name):
    builder = SignatureBuilder()
    field = getattr(builder, field_name)

    if not inspect.ismethod(field) or field_name.startswith('_'):
        return

    argc = len(inspect.signature(field).parameters)

    if argc == 0:
        return

    argv = [None] * argc
    field(*argv)
    assert builder.obj == {}
