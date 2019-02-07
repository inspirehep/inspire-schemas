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
from inspire_schemas.utils import load_schema, validate


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
        material='publication',
        source='source',
        url='url',
        description='description',
        filename='filename',
        original_url='http://www.example.com/original_url'
    )

    expected = [
        {
            'caption': 'caption',
            'key': 'key',
            'label': 'label',
            'material': 'publication',
            'source': 'source',
            'url': 'url',
            'filename': 'filename',
            'original_url': 'http://www.example.com/original_url'
        },
    ]
    result = builder.record

    assert validate(result['figures'], subschema) is None
    assert expected == result['figures']

    for key in subschema['items']['properties'].keys():
        assert key in result['figures'][0]


def test_add_figure_inspire_next():
    schema = load_schema('hep')
    subschema = schema['properties']['figures']

    builder = LiteratureBuilder('test')

    builder.add_figure(
        'key',
        caption='caption',
        label='label',
        material='publication',
        source='source',
        url='url',
        description='description',
        original_url='http://www.example.com/original_url'
    )

    expected = [
        {
            'caption': 'caption',
            'key': 'key',
            'label': 'label',
            'material': 'publication',
            'source': 'source',
            'url': 'url',
            'original_url': 'http://www.example.com/original_url'
        },
    ]
    result = builder.record

    assert validate(result['figures'], subschema) is None
    assert expected == result['figures']


def test_add_figure_fails_on_duplicated_key():
    builder = LiteratureBuilder('test')

    builder.add_figure(
        'key',
        caption='caption',
        label='label',
        material='publication',
        source='source',
        url='url',
        description='description',
        filename='filename',
        original_ur='original_url'
    )

    with pytest.raises(ValueError):
        builder.add_figure(
            'key',
            caption='caption',
            label='label',
            material='publication',
            source='source',
            url='url',
            description='description',
            filename='filename',
            original_ur='original_url'
        )


def test_add_document():
    schema = load_schema('hep')
    subschema = schema['properties']['documents']

    builder = LiteratureBuilder('test')

    builder.add_document(
        'key',
        description='description',
        fulltext=True,
        hidden=True,
        material='preprint',
        original_url='http://www.example.com/original_url',
        source='source',
        url='url',
        filename='filename'
    )

    expected = [
        {
            'description': 'description',
            'fulltext': True,
            'hidden': True,
            'key': 'key',
            'material': 'preprint',
            'original_url': 'http://www.example.com/original_url',
            'source': 'source',
            'url': 'url',
            'filename': 'filename'
        },
    ]
    result = builder.record

    assert validate(result['documents'], subschema) is None
    assert expected == result['documents']

    for key in subschema['items']['properties'].keys():
        assert key in result['documents'][0]


def test_add_document_inspire_next():
    schema = load_schema('hep')
    subschema = schema['properties']['documents']

    builder = LiteratureBuilder('test')

    builder.add_document(
        'key',
        description='description',
        fulltext=True,
        hidden=True,
        material='preprint',
        original_url='http://www.example.com/original_url',
        source='source',
        url='url',
    )

    expected = [
        {
            'description': 'description',
            'fulltext': True,
            'hidden': True,
            'key': 'key',
            'material': 'preprint',
            'original_url': 'http://www.example.com/original_url',
            'source': 'source',
            'url': 'url',
        },
    ]
    result = builder.record

    assert validate(result['documents'], subschema) is None
    assert expected == result['documents']


def test_add_document_fails_on_existing_key():
    builder = LiteratureBuilder('test')
    builder.add_document(
        'key',
        description='description',
        fulltext=True,
        hidden=True,
        material='preprint',
        original_url='http://www.example.com/original_url',
        source='source',
        url='url',
        filename='filename'
    )

    with pytest.raises(ValueError):
        builder.add_document(
            'key',
            description='description',
            fulltext=True,
            hidden=True,
            material='preprint',
            original_url='http://www.example.com/original_url',
            source='source',
            url='url',
            filename='filename'
        )


def test_make_author():
    schema = load_schema('hep')
    subschema = schema['properties']['authors']
    builder = LiteratureBuilder()

    result = builder.make_author(
        'Smith, John',
        affiliations=['CERN', 'SLAC'],
        source='submitter',
        raw_affiliations=['CERN, 1211 Geneva', 'SLAC, Stanford'],
        emails=['john.smith@example.org'],
        ids=[('INSPIRE BAI', 'J.Smith.1')],
        alternative_names=['Johnny Smith']
    )
    expected = {
        'full_name': 'Smith, John',
        'affiliations': [
            {'value': 'CERN'},
            {'value': 'SLAC'},
        ],
        'raw_affiliations': [
            {
                'value': 'CERN, 1211 Geneva',
                'source': 'submitter'
            },
            {
                'value': 'SLAC, Stanford',
                'source': 'submitter',
            }
        ],
        'emails': ['john.smith@example.org'],
        'ids': [
            {
                'schema': 'INSPIRE BAI',
                'value': 'J.Smith.1',
            }
        ],
        'alternative_names': ['Johnny Smith'],
    }

    assert validate([result], subschema) is None
    assert expected == result


def test_add_keyword():
    schema = load_schema('hep')
    subschema = schema['properties']['keywords']
    builder = LiteratureBuilder(source='Publisher')
    builder.add_keyword('29.27.Fh', schema='PACS')

    result = builder.record['keywords']
    expected = [
        {
            'value': '29.27.Fh',
            'schema': 'PACS',
            'source': 'Publisher',
        }
    ]

    assert validate(result, subschema) is None
    assert expected == result


def test_field_not_added_when_only_material():
    builder = LiteratureBuilder(source='Publisher')
    builder.add_publication_info(material='Publication')

    assert 'publication_info' not in builder.record


def test_add_doi_handles_none():
    builder = LiteratureBuilder()
    builder.add_doi(None)

    result = builder.record
    assert 'dois' not in result


def test_add_doi_normalizes_doi():
    schema = load_schema('hep')
    subschema = schema['properties']['dois']
    builder = LiteratureBuilder()
    builder.add_doi('doi.org/10.1234/foo')

    result = builder.record['dois']
    expected = [
        {
            'value': '10.1234/foo',
        }
    ]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_doi_with_invalid_value():
    builder = LiteratureBuilder()
    builder.add_doi('invalid doi value, ignore me')

    result = builder.record
    assert 'dois' not in result


def test_add_license_doesnt_overwrite_name_if_no_url():
    schema = load_schema('hep')
    subschema = schema['properties']['license']
    builder = LiteratureBuilder()
    builder.add_license(license='foo')

    result = builder.record['license']
    expected = [
        {
            'license': 'foo',
        }
    ]

    assert validate(result, subschema) is None
    assert expected == result


def test_repr_handles_source_none():
    builder = LiteratureBuilder()
    assert repr(builder).startswith('LiteratureBuilder(source=None, record={')


def test_repr_handles_source_present():
    builder = LiteratureBuilder('publisher')
    assert repr(builder).startswith(
        "LiteratureBuilder(source='publisher', record={"
    )


def test_add_reference():
    builder = LiteratureBuilder()
    reference = {
        "reference": {
            "authors": [
                {
                    "full_name": "Smith, J."
                }
            ],
            "label": "1",
            "publication_info": {
                "year": 1996
            }
        }
    }
    builder.add_reference(reference)
    assert builder.record['references'] == [reference]


def test_publication_info_public_note():
    schema = load_schema('hep')
    subschema = schema['properties']['public_notes']
    builder = LiteratureBuilder(source="APS")
    builder.add_publication_info(journal_title="Phys. Rev. B")

    expected = [
        {
            'source': 'APS',
            'value': 'Submitted to Phys. Rev. B',
        }
    ]
    result = builder.record['public_notes']

    assert validate(result, subschema) is None
    assert expected == result
    assert 'publication_info' not in builder.record


def test_preprint_date_normalizes_date():
    builder = LiteratureBuilder()
    builder.add_preprint_date('12 April 2010')

    result = builder.record['preprint_date']

    expected = '2010-04-12'

    assert expected == result


def test_imprint_date_normalizes_date():
    builder = LiteratureBuilder()
    builder.add_imprint_date('19 September 2005')

    result = builder.record['imprints']

    expected = [
        {
            'date': '2005-09-19'
        }
    ]

    assert expected == result


def test_add_book_normalizes_date():
    builder = LiteratureBuilder()
    builder.add_book(date='9 November 1990')

    result = builder.record['imprints']

    expected = [
        {
            'date': '1990-11-09'
        }
    ]

    assert expected == result


def test_add_isbn_normalizes_isbn():
    builder = LiteratureBuilder()
    builder.add_isbn(isbn='978-3-642-23908-3')

    result = builder.record['isbns']

    expected = [
        {
            'value': '9783642239083'
        }
    ]

    assert expected == result


def test_add_parent_isbn_normalizes_isbn():
    builder = LiteratureBuilder()
    builder.add_publication_info(parent_isbn='978-3-642-23908-3')

    result = builder.record['publication_info']

    expected = [
        {
            'parent_isbn': '9783642239083'
        }
    ]

    assert expected == result


def test_make_author_handles_none_in_id_value():
    schema = load_schema('hep')
    subschema = schema['properties']['authors']
    builder = LiteratureBuilder()

    result = builder.make_author(
        'Smith, John',
        ids=[('INSPIRE BAI', None)],
    )
    expected = {
        'full_name': 'Smith, John',
    }

    assert validate([result], subschema) is None
    assert expected == result


def test_make_author_handles_none_in_id_schema():
    schema = load_schema('hep')
    subschema = schema['properties']['authors']
    builder = LiteratureBuilder()

    result = builder.make_author(
        'Smith, John',
        ids=[(None, 'J.Smith.1')],
    )
    expected = {
        'full_name': 'Smith, John',
    }

    assert validate([result], subschema) is None
    assert expected == result
