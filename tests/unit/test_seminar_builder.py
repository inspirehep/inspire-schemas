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

import pytest

from inspire_schemas.builders import SeminarBuilder


def test_no_data():
    expected = {
        '_collections': ['Seminars'],
    }
    builder = SeminarBuilder()

    assert builder.record == expected


def test_data_in_init():
    expected = {
        '_collections': ['Seminars'],
        'some_key': 'some_value',
        'some_key_with_list': ['some', 'list'],
    }
    builder = SeminarBuilder(expected)

    assert builder.record == expected


def test_ensure_field_no_field():
    builder = SeminarBuilder()

    assert 'test_field' not in builder.record

    builder._ensure_field('test_field', default_value='test_value')

    assert 'test_field' in builder.record
    assert builder.record['test_field'] == 'test_value'


def test_ensure_field_separate():
    builder = SeminarBuilder()
    obj = {'field_one': 'value'}

    builder._ensure_field('test_field', default_value='test_value', obj=obj)
    builder._ensure_field('field_one', 'wrong_value', obj=obj)

    assert 'test_field' in obj
    assert obj['test_field'] == 'test_value'
    assert obj['field_one'] == 'value'


def test_ensure_list_field_missing():
    builder = SeminarBuilder()

    assert 'list_field' not in builder.record

    builder._ensure_list_field('list_field')

    assert 'list_field' in builder.record
    assert builder.record['list_field'] == []


def test_ensure_list_on_existing():
    builder = SeminarBuilder()

    builder._ensure_list_field('_collections')

    assert builder.record['_collections'] == ['Seminars']


def test_ensure_dict_field_missing():
    builder = SeminarBuilder()
    builder.record['existing_dict'] = {'some_dict': 'some_value'}

    assert 'dict_field' not in builder.record

    builder._ensure_dict_field('dict_field')

    assert 'dict_field' in builder.record
    assert builder.record['dict_field'] == {}


def test_ensure_dict_field_existing():
    builder = SeminarBuilder()
    builder.record['existing_dict'] = {'some_dict': 'some_value'}

    builder._ensure_dict_field('existing_dict')

    assert builder.record['existing_dict'] == {'some_dict': 'some_value'}


def test_sourced_dict_local_source():
    builder = SeminarBuilder(source='global')

    expected = {
        'source': 'local',
        'value': 'foo'
    }

    result = builder._sourced_dict('local', value='foo')

    assert result == expected


def test_sourced_dict_global_source():
    builder = SeminarBuilder(source='global')

    expected = {
        'source': 'global',
        'value': 'foo'
    }

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_sourced_dict_no_source():
    builder = SeminarBuilder()

    expected = {
        'value': 'foo'
    }

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_append_to_field_some_simple_data():
    builder = SeminarBuilder()

    builder._append_to('test_field', 'first_element')

    assert 'test_field' in builder.record
    assert builder.record['test_field'] == ['first_element']

    builder._append_to('test_field', 'second_element')

    assert builder.record['test_field'] == ['first_element', 'second_element']


def test_append_to_field_duplicated_simple_data():
    builder = SeminarBuilder()

    builder._append_to('test_field', 'first_element')
    builder._append_to('test_field', 'second_element')
    builder._append_to('test_field', 'first_element')
    builder._append_to('test_field', 'second_element')

    assert builder.record['test_field'] == ['first_element', 'second_element']


def test_append_to_field_complex_data():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {
            'key': 'another_value',
            'something': 'else'
        }
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],

    }

    builder = SeminarBuilder()

    builder._append_to('some_field', element_one)
    assert builder.record['some_field'] == [element_one]

    builder._append_to('some_field', element_two)
    assert builder.record['some_field'] == [element_one, element_two]


def test_append_to_field_dumplicated_complex_data():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {
            'key': 'another_value',
            'something': 'else'
        }
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],

    }

    builder = SeminarBuilder()

    builder._append_to('some_field', element_one)
    builder._append_to('some_field', element_two)
    builder._append_to('some_field', element_one)
    builder._append_to('some_field', element_two)

    assert builder.record['some_field'] == [element_one, element_two]


def test_append_to_field_from_kwargs():
    element_one = {
        'key': 'value',
        'list_key': ['some', 'values'],
        'dict_key': {
            'key': 'another_value',
            'something': 'else'
        }
    }

    element_two = {
        'key': 'value2',
        'other_list_key': ['some', 'values'],

    }

    builder = SeminarBuilder()

    builder._append_to('some_field', **element_one)
    assert builder.record['some_field'] == [element_one]

    builder._append_to('some_field', element_two)
    assert builder.record['some_field'] == [element_one, element_two]


def test_set_address():
    expected = {
        '_collections': ['Seminars'],
        'address': {
            'cities': ['Anaheim'],
            'country_code': 'US',
            'state': 'CA'
        }
    }
    builder = SeminarBuilder()
    builder.set_address(
        cities=['Anaheim'],
        country_code='US',
        state='CA'
    )

    assert builder.record == expected


def test_add_contact():
    expected = [
        {
            'name': 'name',
            'email': 'email',
            'curated_relation': True,
            'record': {'$ref': 'http://nothing'}
        },
        {
            'name': 'name2',
            'email': 'email2'
        },
        {
            'name': 'name3',
        },
        {
            'email': 'email3'
        }
    ]

    builder = SeminarBuilder()
    builder.add_contact(
        name='name', email='email', curated_relation=True, record='http://nothing'
    )
    builder.add_contact(
        name='name2',
        email='email2'
    )
    builder.add_contact(name='name3')
    builder.add_contact(email='email3')
    assert builder.record['contact_details'] == expected


def test_add_inspire_categories():
    expected = {
        '_collections': ['Seminars'],
        'inspire_categories': [{'source': 'arxiv', 'term': 'Computing'}]
    }
    builder = SeminarBuilder()
    builder.add_inspire_categories(['Computing'], 'arxiv')

    assert builder.record == expected


def test_add_keyword():
    expected = {
        '_collections': ['Seminars'],
        'keywords': [
            {'schema': 'INSPIRE', 'source': 'arxiv', 'value': '29.27.Fh'}
        ]
    }
    builder = SeminarBuilder()
    builder.add_keyword('29.27.Fh', schema='INSPIRE', source='arxiv')

    assert builder.record == expected


def test_add_public_note():
    expected = {
        '_collections': ['Seminars'],
        'public_notes': [{'source': 'http://some/source', 'value': 'Note'}]
    }
    builder = SeminarBuilder()
    builder.add_public_note('Note', 'http://some/source')

    assert builder.record == expected


def test_add_series():
    series_name = 'Warsaw Symposium on Elementary Particle Physics'
    expected = {
        '_collections': ['Seminars'],
        'series': [
            {
                'name': series_name,
                'number': 1
            }
        ],
    }
    builder = SeminarBuilder()
    builder.add_series(series_name, number=1)

    assert builder.record == expected


def test_set_title():
    expected = {
        '_collections': ['Seminars'],
        'title': {
            'title': 'Electronic Components Conference',
            'subtitle': 'A Real Sub-Title'
        }
    }
    builder = SeminarBuilder()
    builder.set_title('Electronic Components Conference', 'A Real Sub-Title')

    assert builder.record == expected


def test_set_title_without_subtitle():
    expected = {
        '_collections': ['Seminars'],
        'title': {
            'title': 'Electronic Components Conference',
        }
    }
    builder = SeminarBuilder()
    builder.set_title('Electronic Components Conference')

    assert builder.record == expected


def test_add_url():
    builder = SeminarBuilder()
    builder.add_url('http://www.example.com')

    expected = {
        '_collections': ['Seminars'],
        'urls': [
            {'value': 'http://www.example.com'},
        ],
    }

    assert builder.record == expected


def test_add_join_url():
    builder = SeminarBuilder()
    builder.add_join_url('http://www.example.com/calls/join/seminar')

    expected = {
        '_collections': ['Seminars'],
        'join_urls': [
            {'value': 'http://www.example.com/calls/join/seminar'},
        ],
    }

    assert builder.record == expected


def test_set_end_datetime():
    expected = {
        '_collections': ['Seminars'],
        'end_datetime': '4254-10-11T22:18:22.063Z'
    }
    builder = SeminarBuilder()
    builder.set_end_datetime('4254-10-11T22:18:22.063Z')

    assert builder.record == expected


def test_set_start_datetime():
    expected = {
        '_collections': ['Seminars'],
        'start_datetime': '4254-10-11T22:18:22.063Z'
    }
    builder = SeminarBuilder()
    builder.set_start_datetime('4254-10-11T22:18:22.063Z')

    assert builder.record == expected


def test_set_abstract_without_source():
    expected = {
        '_collections': ['Seminars'],
        'abstract': {'value': 'lorem ipsum'}
    }
    builder = SeminarBuilder()
    builder.set_abstract('lorem ipsum')

    assert builder.record == expected


def test_set_abstract_with_source():
    expected = {
        '_collections': ['Seminars'],
        'abstract': {'value': 'lorem ipsum', 'source': 'arxiv'}
    }
    builder = SeminarBuilder(source='arxiv')
    builder.set_abstract('lorem ipsum')

    assert builder.record == expected


def test_sanitization_of_abstract():
    expected = '<div>Some text <em>emphasized</em> linking to <a href="http://example.com">'\
        'http://example.com</a></div>'
    description = '<div>Some <span>text</span> <em class="shiny">emphasized</em> linking to '\
        'http://example.com</div>'
    builder = SeminarBuilder()
    builder.set_abstract(description)

    assert builder.record['abstract']['value'] == expected


def test_set_timezone():
    expected = {
        '_collections': ['Seminars'],
        'timezone': 'Europe/Zurich'
    }
    builder = SeminarBuilder()
    builder.set_timezone('Europe/Zurich')

    assert builder.record == expected


def test_add_speaker():
    expected = [
        {
            'name': 'Author1',
            'record': {'$ref': 'http://author/1'}
        },
        {
            'name': 'Another',
            'record': {'$ref': 'http://author/another'},
            'affiliations': [
                {'value': 'CERN', 'record': {'$ref': 'http://institution/cern'}},
                {'value': 'Turkiye Kareli Gomlek Giyenler Ensitisu'}
            ]
        },
        {
            'name': 'Guy, Some',
        },
    ]

    builder = SeminarBuilder()
    builder.add_speaker(
        name='author1', record={'$ref': 'http://author/1'}
    )
    builder.add_speaker(
        name='Another',
        record={'$ref': 'http://author/another'},
        affiliations=[
            {'value': 'CERN', 'record': {'$ref': 'http://institution/cern'}},
            {'value': 'Turkiye Kareli Gomlek Giyenler Ensitisu'}
        ]
    )
    builder.add_speaker(name='some guy')
    assert builder.record['speakers'] == expected


def test_add_literature_record():
    expected = [
        {
            'record': {'$ref': 'http://literature/1'}
        },
        {
            'record': {'$ref': 'http://literature/another'},
            'curated_relation': True
        },
    ]

    builder = SeminarBuilder()
    builder.add_literature_record(
        record={'$ref': 'http://literature/1'}
    )
    builder.add_literature_record(
        record={'$ref': 'http://literature/another'},
        curated_relation=True
    )
    assert builder.record['literature_records'] == expected
