# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2019 CERN.
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

from __future__ import absolute_import, division, print_function

from inspire_schemas.api import load_schema, validate
from inspire_schemas.readers.literature import LiteratureReader


def test_abstract():
    schema = load_schema('hep')
    subschema = schema['properties']['abstracts']

    record = {
        'abstracts': [
            {
                'source': 'arXiv',
                'value': 'Probably not.',
            },
        ],
    }
    assert validate(record['abstracts'], subschema) is None

    expected = 'Probably not.'
    result = LiteratureReader(record).abstract

    assert expected == result


def test_arxiv_categories():
    schema = load_schema('hep')
    subschema = schema['properties']['arxiv_eprints']

    record = {
        'arxiv_eprints': [
            {
                'categories': [
                    'hep-th',
                    'hep-ph',
                ],
                'value': '1612.08928',
            },
        ],
    }
    assert validate(record['arxiv_eprints'], subschema) is None

    expected = ['hep-th', 'hep-ph']
    result = LiteratureReader(record).arxiv_categories

    assert expected == result


def test_arxiv_id():
    schema = load_schema('hep')
    subschema = schema['properties']['arxiv_eprints']

    record = {
        'arxiv_eprints': [
            {
                'categories': [
                    'hep-th',
                    'hep-ph',
                ],
                'value': '1612.08928',
            },
        ],
    }
    assert validate(record['arxiv_eprints'], subschema) is None

    expected = '1612.08928'
    result = LiteratureReader(record).arxiv_id

    assert expected == result


def test_collaborations():
    schema = load_schema('hep')
    subschema = schema['properties']['collaborations']

    record = {
        'collaborations': [
            {'value': 'CMS'},
        ],
    }
    assert validate(record['collaborations'], subschema) is None

    expected = ['CMS']
    result = LiteratureReader(record).collaborations

    assert expected == result


def test_document_types():
    schema = load_schema('hep')
    subschema = schema['properties']['document_type']

    record = {
        'document_type': [
            'article',
        ],
    }
    assert validate(record['document_type'], subschema) is None

    expected = ['article']
    result = LiteratureReader(record).document_types

    assert expected == result


def test_doi():
    schema = load_schema('hep')
    subschema = schema['properties']['dois']

    record = {
        'dois': [
            {'value': '10.1016/0029-5582(61)90469-2'},
        ],
    }
    assert validate(record['dois'], subschema) is None

    expected = '10.1016/0029-5582(61)90469-2'
    result = LiteratureReader(record).doi

    assert expected == result


def test_journal_issue():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'journal_issue': '5'},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '5'
    result = LiteratureReader(record).journal_issue

    assert expected == result


def test_journal_title():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'journal_title': 'Phys.Part.Nucl.Lett.'},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = 'Phys.Part.Nucl.Lett.'
    result = LiteratureReader(record).journal_title

    assert expected == result


def test_journal_volume():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'journal_volume': 'D94'},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = 'D94'
    result = LiteratureReader(record).journal_volume

    assert expected == result


def test_inspire_categories():
    schema = load_schema('hep')
    subschema = schema['properties']['inspire_categories']

    record = {
        'inspire_categories': [
            {'term': 'Experiment-HEP'},
            {'term': 'Quantum Physics'},
            {'term': 'Condensed Matter'},
        ],
    }
    assert validate(record['inspire_categories'], subschema) is None

    expected = ['Experiment-HEP', 'Quantum Physics', 'Condensed Matter']
    result = LiteratureReader(record).inspire_categories

    assert expected == result


def test_language():
    schema = load_schema('hep')
    subschema = schema['properties']['languages']

    record = {
        'languages': [
            'it',
        ],
    }
    assert validate(record['languages'], subschema) is None

    expected = 'it'
    result = LiteratureReader(record).language

    assert expected == result


def test_language_falls_back_to_english():
    record = {}

    expected = 'en'
    result = LiteratureReader(record).language

    assert expected == result


def test_keywords():
    schema = load_schema('hep')
    subschema = schema['properties']['keywords']

    record = {
        'keywords': [
            {
                'schema': 'INSPIRE',
                'value': 'CKM matrix',
            },
        ],
    }
    assert validate(record['keywords'], subschema) is None

    expected = ['CKM matrix']
    result = LiteratureReader(record).keywords

    assert expected == result


def test_method():
    schema = load_schema('hep')
    subschema = schema['properties']['acquisition_source']

    record = {
        'acquisition_source': {
            'method': 'oai',
            'source': 'arxiv',
        },
    }
    assert validate(record['acquisition_source'], subschema) is None

    expected = 'oai'
    result = LiteratureReader(record).method

    assert expected == result


def test_page_artid_handles_artid():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'artid': '054021'},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '054021'
    result = LiteratureReader(record).get_page_artid()

    assert expected == result


def test_get_page_artid_handles_page_range():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {
                'page_end': '588',
                'page_start': '579',
            },
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '579-588'
    result = LiteratureReader(record).get_page_artid()

    assert expected == result


def test_get_page_range_not_artid():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {
                'page_end': '432',
                'page_start': '402',
                "artid": "18184",

            },
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '402-432'
    result = LiteratureReader(record).get_page_artid()

    assert expected == result


def test_peer_reviewed():
    schema = load_schema('hep')
    subschema = schema['properties']['refereed']

    record = {'refereed': True}
    assert validate(record['refereed'], subschema) is None

    expected = 1
    result = LiteratureReader(record).peer_reviewed

    assert expected == result


def test_publication_date():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'year': 2017},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '2017'
    result = LiteratureReader(record).publication_date

    assert expected == result


def test_is_published():
    schema = load_schema('hep')
    dois_schema = schema['properties']['dois']
    publication_info_schema = schema['properties']['publication_info']

    record = {
        'dois': [
            {'value': '10.1016/0029-5582(61)90469-2'},
        ],
        'publication_info': [
            {'journal_title': 'Nucl.Phys.'},
        ],
    }
    assert validate(record['dois'], dois_schema) is None
    assert validate(record['publication_info'], publication_info_schema) is None

    assert LiteratureReader(record).is_published


def test_source():
    schema = load_schema('hep')
    subschema = schema['properties']['acquisition_source']

    record = {
        'acquisition_source': {
            'method': 'oai',
            'source': 'arxiv',
        },
    }
    assert validate(record['acquisition_source'], subschema) is None

    expected = 'arxiv'
    result = LiteratureReader(record).source

    assert expected == result


def test_subtitle():
    schema = load_schema('hep')
    subschema = schema['properties']['titles']

    record = {
        'titles': [
            {
                'subtitle': 'A mathematical exposition',
                'title': 'The General Theory of Relativity',
            },
        ],
    }
    assert validate(record['titles'], subschema) is None

    expected = 'A mathematical exposition'
    result = LiteratureReader(record).subtitle

    assert expected == result


def test_title():
    schema = load_schema('hep')
    subschema = schema['properties']['titles']

    record = {
        'titles': [
            {
                'subtitle': 'A mathematical exposition',
                'title': 'The General Theory of Relativity',
            },
        ],
    }
    assert validate(record['titles'], subschema) is None

    expected = 'The General Theory of Relativity'
    result = LiteratureReader(record).title

    assert expected == result


def test_page_artid_handles_artid():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {'artid': '054021'},
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '054021'
    result = LiteratureReader(record).get_page_artid()

    assert expected == result


def test_get_page_artid_handles_page_range():
    schema = load_schema('hep')
    subschema = schema['properties']['publication_info']

    record = {
        'publication_info': [
            {
                'page_end': '588',
                'page_start': '579',
            },
        ],
    }
    assert validate(record['publication_info'], subschema) is None

    expected = '579-588'
    result = LiteratureReader(record).get_page_artid()

    assert expected == result
