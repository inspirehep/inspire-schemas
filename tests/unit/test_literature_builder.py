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

import pytest

from inspire_schemas.builders.literature import LiteratureBuilder, is_citeable
from inspire_schemas.utils import load_schema


@pytest.mark.parametrize(
    'expected_result,formdata',
    [
        (
            True,
            [
                {
                    'journal_title': 'High Energy Physics Libraries Webzine',
                    'journal_volume': '192',
                    'artid': '2550'
                }
            ]
        ), (
            True,
            [
                {
                    'journal_title': 'High Energy Physics Libraries Webzine',
                    'journal_volume': '192',
                    'page_start': '28'
                }
            ]
        ), (
            False,
            [
                {
                    'journal_title': 'High Energy Physics Libraries Webzine',
                    'journal_volume': '192',
                }
            ]
        ), (
            False,
            [
                {
                    'journal_title': 'High Energy Physics Libraries Webzine',
                    'page_start': '25'
                }
            ]
        )
    ]
)
def test_is_citeable(expected_result, formdata):
    assert is_citeable(formdata) is expected_result


def test_append_to():
    formdata = ''
    builder = LiteratureBuilder("test")
    expected_result = None
    builder._append_to('test_field', formdata)
    assert builder.record.get('test_field') is expected_result
    formdata = 'value'
    expected_result = ['value']
    builder._append_to('test_field_2', formdata)
    assert builder.record.get('test_field_2') == expected_result


def test_sourced_dict_local_source():
    builder = LiteratureBuilder('global')

    expected = {
        'source': 'local',
        'value': 'foo'
    }

    result = builder._sourced_dict('local', value='foo')

    assert result == expected


def test_sourced_dict_global_source():
    builder = LiteratureBuilder('global')

    expected = {
        'source': 'global',
        'value': 'foo'
    }

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_sourced_dict_no_source():
    builder = LiteratureBuilder()

    expected = {
        'value': 'foo'
    }

    result = builder._sourced_dict(None, value='foo')

    assert result == expected


def test_add_figure():
    schema = load_schema('hep')
    subschema = schema['properties']['figures']

    builder = LiteratureBuilder('test')

    builder.add_figure(
        'key',
        caption='caption',
        label='label',
        material='material',
        source='source',
        url='url',
    )

    expected = [
        {
            'caption': 'caption',
            'key': 'key',
            'label': 'label',
            'material': 'material',
            'source': 'source',
            'url': 'url',
        },
    ]
    result = builder.record

    assert expected == result['figures']

    for key in subschema['items']['properties'].keys():
        assert key in result['figures'][0]


def test_add_document():
    schema = load_schema('hep')
    subschema = schema['properties']['documents']

    builder = LiteratureBuilder('test')

    builder.add_document(
        'key',
        description='description',
        fulltext=True,
        hidden=True,
        material='material',
        original_url='original_url',
        source='source',
        url='url',
    )

    expected = [
        {
            'description': 'description',
            'fulltext': True,
            'hidden': True,
            'key': 'key',
            'material': 'material',
            'original_url': 'original_url',
            'source': 'source',
            'url': 'url',
        },
    ]
    result = builder.record

    assert expected == result['documents']

    for key in subschema['items']['properties'].keys():
        assert key in result['documents'][0]
