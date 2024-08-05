# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2019 CERN.
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

import jsonschema
import pytest

from inspire_schemas.builders import ConferenceBuilder
from inspire_schemas.utils import load_schema, validate


def test_no_data():
    expected = {
        '_collections': ['Conferences'],
    }
    builder = ConferenceBuilder()

    assert builder.record == expected


def test_data_in_init():
    expected = {
        '_collections': ['Conferences'],
        'some_key': 'some_value',
        'some_key_with_list': ['some', 'list'],
    }
    builder = ConferenceBuilder(expected)

    assert builder.record == expected


def test_ensure_field_no_field():
    builder = ConferenceBuilder()

    assert 'test_field' not in builder.record

    builder._ensure_field('test_field', default_value='test_value')

    assert 'test_field' in builder.record
    assert builder.record['test_field'] == 'test_value'


def test_ensure_field_separate():
    builder = ConferenceBuilder()
    obj = {'field_one': 'value'}

    builder._ensure_field('test_field', default_value='test_value', obj=obj)
    builder._ensure_field('field_one', 'wrong_value', obj=obj)

    assert 'test_field' in obj
    assert obj['test_field'] == 'test_value'
    assert obj['field_one'] == 'value'


def test_ensure_list_field_missing():
    builder = ConferenceBuilder()

    assert 'list_field' not in builder.record

    builder._ensure_list_field('list_field')

    assert 'list_field' in builder.record
    assert builder.record['list_field'] == []


def test_ensure_list_on_existing():
    builder = ConferenceBuilder()

    builder._ensure_list_field('_collections')

    assert builder.record['_collections'] == ['Conferences']


def test_ensure_dict_field_missing():
    builder = ConferenceBuilder()
    builder.record['existing_dict'] = {'some_dict': 'some_value'}

    assert 'dict_field' not in builder.record

    builder._ensure_dict_field('dict_field')

    assert 'dict_field' in builder.record
    assert builder.record['dict_field'] == {}


def test_ensure_dict_field_existing():
    builder = ConferenceBuilder()
    builder.record['existing_dict'] = {'some_dict': 'some_value'}

    builder._ensure_dict_field('existing_dict')

    assert builder.record['existing_dict'] == {'some_dict': 'some_value'}


def test_sourced_dict_local_source():
    builder = ConferenceBuilder(source='global')

    expected = {'source': 'local', 'value': 'foo'}

    result = builder._sourced_dict('local', value='foo')

    assert result == expected


def test_sourced_dict_global_source():
    builder = ConferenceBuilder(source='global')

    expected = {'source': 'global', 'value': 'foo'}

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_sourced_dict_no_source():
    builder = ConferenceBuilder()

    expected = {'value': 'foo'}

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_append_to_field_some_simple_data():
    builder = ConferenceBuilder()

    builder._append_to('test_field', 'first_element')

    assert 'test_field' in builder.record
    assert builder.record['test_field'] == ['first_element']

    builder._append_to('test_field', 'second_element')

    assert builder.record['test_field'] == ['first_element', 'second_element']


def test_append_to_field_duplicated_simple_data():
    builder = ConferenceBuilder()

    builder._append_to('test_field', 'first_element')
    builder._append_to('test_field', 'second_element')
    builder._append_to('test_field', 'first_element')
    builder._append_to('test_field', 'second_element')

    assert builder.record['test_field'] == ['first_element', 'second_element']


def test_append_to_field_complex_data():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {'key': 'another_value', 'something': 'else'},
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],
    }

    builder = ConferenceBuilder()

    builder._append_to('some_field', element_one)
    assert builder.record['some_field'] == [element_one]

    builder._append_to('some_field', element_two)
    assert builder.record['some_field'] == [element_one, element_two]


def test_append_to_field_dumplicated_complex_data():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {'key': 'another_value', 'something': 'else'},
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],
    }

    builder = ConferenceBuilder()

    builder._append_to('some_field', element_one)
    builder._append_to('some_field', element_two)
    builder._append_to('some_field', element_one)
    builder._append_to('some_field', element_two)

    assert builder.record['some_field'] == [element_one, element_two]


def test_append_to_field_from_kwargs():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {'key': 'another_value', 'something': 'else'},
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],
    }

    builder = ConferenceBuilder()

    builder._append_to('some_field', **element_one)
    assert builder.record['some_field'] == [element_one]

    builder._append_to('some_field', element_two)
    assert builder.record['some_field'] == [element_one, element_two]


def test_add_private_note_with_source():
    expected = {
        '_collections': ['Conferences'],
        '_private_notes': [{'source': 'http://some/source', 'value': 'Note'}],
    }
    builder = ConferenceBuilder()
    builder.add_private_note('Note', 'http://some/source')

    assert builder.record == expected


def test_add_private_note_without_source():
    schema = load_schema('conferences')
    subschema = schema['properties']['_private_notes']
    expected = {'_collections': ['Conferences'], '_private_notes': [{'value': 'Note'}]}
    builder = ConferenceBuilder()
    builder.add_private_note('Note', '')

    result = builder.record

    assert result == expected
    assert validate(result['_private_notes'], subschema) is None


def test_add_acronym():
    schema = load_schema('conferences')
    subschema = schema['properties']['acronyms']

    expected = {'_collections': ['Conferences'], 'acronyms': ['SUSY 2018', 'SUSY 2019']}
    builder = ConferenceBuilder()
    builder.add_acronym('SUSY 2018')
    builder.add_acronym('SUSY 2019')

    result = builder.record

    assert result == expected
    assert validate(result['acronyms'], subschema) is None


def test_add_empry_acronym():
    expected = {
        '_collections': ['Conferences'],
    }
    builder = ConferenceBuilder()
    builder.add_acronym('')

    assert builder.record == expected


def test_add_address():
    schema = load_schema('conferences')
    subschema = schema['properties']['addresses']

    expected = {
        '_collections': ['Conferences'],
        'addresses': [{'cities': ['Anaheim'], 'country_code': 'US', 'state': 'CA'}],
    }
    builder = ConferenceBuilder()
    builder.add_address(cities=['Anaheim'], country_code='US', state='CA')

    result = builder.record

    assert result == expected
    assert validate(result['addresses'], subschema) is None


def test_add_alternative_title():
    schema = load_schema('conferences')
    subschema = schema['properties']['alternative_titles']

    expected = {
        '_collections': ['Conferences'],
        'alternative_titles': [{'title': 'Foo', 'subtitle': 'Bar', 'source': 'arXiv'}],
    }
    builder = ConferenceBuilder()
    builder.add_alternative_title('Foo', 'Bar', 'arXiv')

    result = builder.record

    assert result == expected
    assert validate(result['alternative_titles'], subschema) is None


def test_add_cnum():
    schema = load_schema('conferences')
    subschema = schema['properties']['cnum']

    expected = {'_collections': ['Conferences'], 'cnum': 'C75-09-03.1'}
    builder = ConferenceBuilder()
    builder.set_cnum('C75-09-03.1')

    result = builder.record

    assert result == expected
    assert validate(result['cnum'], subschema) is None


def test_add_empty_cnum():
    expected = {
        '_collections': ['Conferences'],
    }
    builder = ConferenceBuilder()
    builder.set_cnum()

    assert builder.record == expected


def test_add_contact():
    expected = [
        {
            'name': 'name',
            'email': 'email',
            'curated_relation': True,
            'record': {'$ref': 'http://nothing'},
        },
        {'name': 'name2', 'email': 'email2'},
        {
            'name': 'name3',
        },
        {'email': 'email3'},
    ]

    builder = ConferenceBuilder()
    builder.add_contact(
        name='name', email='email', curated_relation=True, record='http://nothing'
    )
    builder.add_contact(name='name2', email='email2')
    builder.add_contact(name='name3')
    builder.add_contact(email='email3')
    assert builder.record['contact_details'] == expected


def test_add_external_system_identifiers():
    builder = ConferenceBuilder()
    builder.add_external_system_identifier('12345', 'osti')

    result = builder.record['external_system_identifiers']
    expected = [
        {
            'value': '12345',
            'schema': 'osti',
        }
    ]

    assert expected == result


def test_add_several_external_system_identifier():
    builder = ConferenceBuilder()
    builder.add_external_system_identifier('5758037', 'osti')
    builder.add_external_system_identifier('1992PhRvD..45..124K', 'ADS')

    result = builder.record['external_system_identifiers']
    expected = [
        {
            'value': '5758037',
            'schema': 'osti',
        },
        {
            'value': '1992PhRvD..45..124K',
            'schema': 'ADS',
        },
    ]

    assert expected == result


def test_add_external_system_identifier_kwargs():
    builder = ConferenceBuilder()
    builder.add_external_system_identifier(schema='osti', value='12345')

    result = builder.record['external_system_identifiers']
    expected = [
        {
            'value': '12345',
            'schema': 'osti',
        }
    ]

    assert expected == result


def test_add_external_system_identifier_empty_kwargs():
    builder = ConferenceBuilder()
    builder.add_external_system_identifier(schema='', value='')

    assert 'external_system_identifiers' not in builder.record


def test_add_inspire_categories():
    schema = load_schema('conferences')
    subschema = schema['properties']['inspire_categories']

    expected = {
        '_collections': ['Conferences'],
        'inspire_categories': [{'source': 'arxiv', 'term': 'Computing'}],
    }
    builder = ConferenceBuilder()
    builder.add_inspire_categories(['Computing'], 'arxiv')

    result = builder.record

    assert result == expected
    assert validate(result['inspire_categories'], subschema) is None


def test_add_keyword():
    expected = {
        '_collections': ['Conferences'],
        'keywords': [{'schema': 'INSPIRE', 'source': 'arxiv', 'value': '29.27.Fh'}],
    }
    builder = ConferenceBuilder()
    builder.add_keyword('29.27.Fh', schema='INSPIRE', source='arxiv')

    assert builder.record == expected


def test_add_public_note():
    expected = {
        '_collections': ['Conferences'],
        'public_notes': [{'source': 'http://some/source', 'value': 'Note'}],
    }
    builder = ConferenceBuilder()
    builder.add_public_note('Note', 'http://some/source')

    assert builder.record == expected


def test_add_series():
    series_name = 'Warsaw Symposium on Elementary Particle Physics'
    expected = {
        '_collections': ['Conferences'],
        'series': [{'name': series_name, 'number': 1}],
    }
    builder = ConferenceBuilder()
    builder.add_series(series_name, number=1)

    assert builder.record == expected


def test_conference_builder_title_required():
    builder = ConferenceBuilder()

    with pytest.raises(jsonschema.exceptions.ValidationError):
        builder.validate_record()


def test_add_title():
    expected = {
        '_collections': ['Conferences'],
        'titles': [
            {
                'title': 'Electronic Components Conference',
                'subtitle': 'A Real Sub-Title',
            }
        ],
    }
    builder = ConferenceBuilder()
    builder.add_title('Electronic Components Conference', 'A Real Sub-Title')

    assert builder.record == expected


def test_add_url():
    builder = ConferenceBuilder()
    builder.add_url('http://www.example.com')

    expected = {
        '_collections': ['Conferences'],
        'urls': [
            {'value': 'http://www.example.com'},
        ],
    }

    assert builder.record == expected


def test_set_core():
    builder = ConferenceBuilder()
    builder.set_core()

    assert builder.record['core'] is True

    builder.set_core(False)

    assert builder.record['core'] is False


def test_set_closing_date():
    expected = {'_collections': ['Conferences'], 'closing_date': '1978-04-26'}
    builder = ConferenceBuilder()
    builder.set_closing_date('1978-04-26')

    assert builder.record == expected


def test_set_opening_date():
    expected = {'_collections': ['Conferences'], 'opening_date': '1978-04-26'}
    builder = ConferenceBuilder()
    builder.set_opening_date('1978-04-26')

    assert builder.record == expected


def test_set_short_description_without_source():
    expected = {
        '_collections': ['Conferences'],
        'short_description': {'value': 'lorem ipsum'},
    }
    builder = ConferenceBuilder()
    builder.set_short_description('lorem ipsum')

    assert builder.record == expected


def test_set_short_description_with_source():
    expected = {
        '_collections': ['Conferences'],
        'short_description': {'value': 'lorem ipsum', 'source': 'arxiv'},
    }
    builder = ConferenceBuilder(source='arxiv')
    builder.set_short_description('lorem ipsum')

    assert builder.record == expected


def test_sanitization_of_short_description():
    expected = (
        '<div>Some text <em>emphasized</em> linking to <a href="http://example.com">'
        'http://example.com</a></div>'
    )
    description = (
        '<div>Some <span>text</span> <em class="shiny">emphasized</em> linking to '
        'http://example.com</div>'
    )
    builder = ConferenceBuilder()
    builder.set_short_description(description)

    assert builder.record['short_description']['value'] == expected
