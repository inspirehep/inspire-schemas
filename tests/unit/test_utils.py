# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016, 2017 CERN.
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

import contextlib
import json
import os

import mock
import pytest
import six

from inspire_schemas import errors, utils


def test_classify_field_returns_none_on_falsy_value():
    assert utils.classify_field('') is None


def test_classify_field_returns_none_on_non_string_value():
    assert utils.classify_field(0) is None


def test_classify_field_returns_category_for_arxiv_category():
    expected = 'Math and Math Physics'
    result = utils.classify_field('math.AG')

    assert expected == result


def test_classify_field_returns_category_for_inspire_category():
    expected = 'Astrophysics'
    result = utils.classify_field('Astrophysics')

    assert expected == result


def test_classify_field_normalizes_arxiv_category():
    expected = 'Math and Math Physics'
    result = utils.classify_field('math-dg')

    assert expected == result


def test_classify_field_returns_other_if_category_not_found():
    expected = 'Other'
    result = utils.classify_field('quant-bio')

    assert expected == result


def test_classify_field_ignores_case():
    expected = 'Astrophysics'
    result = utils.classify_field('ASTRO-PH.CO')

    assert expected == result


def test_normalize_arxiv_category_returns_input_for_correct_category():
    expected = 'hep-th'
    result = utils.normalize_arxiv_category('hep-th')

    assert expected == result


def test_normalize_arxiv_category_returns_input_for_inexistent_category():
    expected = u'😃'
    result = utils.normalize_arxiv_category(u'😃')

    assert expected == result


def test_normalize_arxiv_category_returns_existing_category_for_obsolete():
    expected = 'math.FA'
    result = utils.normalize_arxiv_category('funct-an')

    assert expected == result


def test_normalize_arxiv_category_returns_existing_category_for_wrong_caps():
    expected = 'hep-th'
    result = utils.normalize_arxiv_category('HeP-Th')

    assert expected == result


def test_normalize_arxiv_category_returns_existing_category_when_dot_is_dash():
    expected = 'math.FA'
    result = utils.normalize_arxiv_category('math-fa')

    assert expected == result


@pytest.mark.parametrize(
    'schema,expected',
    (
        ('hep.json', 'hep.json'),
        ('elements/id.json', 'elements/id.json'),
        ('hep', 'hep.json'),
        ('/hep.json', 'hep.json'),
        ('/something/../hep.json', 'hep.json'),
        ('file://somewhe.re/over/the/rainbow/hep.json', 'hep.json'),
        ('../../../../../hep.json', 'hep.json'),
        ('http://somewhe.re/../../../../../hep.json', 'hep.json'),
    ),
    ids=[
        'relative simple path',
        'relative subfolder path',
        'relative simlple path without extension',
        'absolute path',
        'dotted_path',
        'full url',
        'too many dotted relative path',
        'too many dotted full url',
    ],
)
def test_get_schema_path_positive(schema, expected):
    schema_path = utils.get_schema_path(schema)

    assert schema_path == os.path.join(utils._schema_root_path, expected)


@mock.patch('os.path.exists')
def test_get_resolved_schema_path(mock_exists):
    schema_path = utils.get_schema_path(schema='hep.json', resolved=True)
    mock_exists.side_effect = \
        lambda x: x == os.path.join(utils._resolved_schema_root_path, 'hep.json')
    assert schema_path == os.path.join(utils._resolved_schema_root_path, 'hep.json')


@pytest.mark.parametrize(
    'schema',
    (
        'Go and boil your bottoms, sons of a silly person!',
        '../../../../../../etc/passwd',
    ),
    ids=[
        'non existing path',
        'existing malicious path',
    ],
)
def test_get_schema_path_negative(schema):
    with pytest.raises(errors.SchemaNotFound):
        utils.get_schema_path(schema)


@mock.patch('inspire_schemas.utils.RefResolver.resolve_remote')
@mock.patch('inspire_schemas.utils.super')
def test_local_ref_resolver_proxied(mock_super, mock_resolve_remote):
    mock_resolve_remote.side_effect = lambda *x: x[0]
    mock_super.side_effect = lambda *x: utils.RefResolver

    class MockResolver(utils.LocalRefResolver):
        """Needed to be able to call the resolve_remote function on the
        LocalRefResolver without having to instantiate it on both python2 and
        3 as they handle the unbound methods differently.
        """
        def __init__(self):
            pass

    result = MockResolver().resolve_remote('some path')
    assert result == 'some path'


@mock.patch('inspire_schemas.utils.RefResolver.resolve_remote')
@mock.patch('inspire_schemas.utils.super')
@mock.patch('inspire_schemas.utils.get_schema_path')
def test_local_ref_resolver_adapted(mock_get_schema_path, mock_super,
                                    mock_resolve_remote):
    def _mocked_resolve_remote(uri):
        if uri.startswith('file://'):
            return uri

        raise ValueError()

    class MockResolver(utils.LocalRefResolver):
        """Needed to be able to call the resolve_remote function on the
        LocalRefResolver without having to instantiate it on both python2 and
        3 as they handle the unbound methods differently.
        """
        def __init__(self):
            pass

    mock_resolve_remote.side_effect = _mocked_resolve_remote
    mock_super.side_effect = lambda *x: utils.RefResolver
    mock_get_schema_path.side_effect = lambda *args: ' '.join(args)

    result = MockResolver().resolve_remote('some path')
    assert result == 'file://some path'


@mock.patch('inspire_schemas.utils.open')
@mock.patch('inspire_schemas.utils.get_schema_path')
def test_load_schema_with_schema_key(mock_get_schema_path, mock_open):
    myschema = {
        '$schema': {
            'Sir Robin': 'The fleeing brave',
            'shrubbery': 'almaciga',

        }
    }
    mock_open.side_effect = \
        lambda x: contextlib.closing(six.StringIO(json.dumps(myschema)))
    mock_get_schema_path.side_effect = \
        lambda x, y: 'And his nostrils ripped and his bottom burned off'

    loaded_schema = utils.load_schema('And gallantly he chickened out')

    assert loaded_schema == myschema


def test_split_page_artid_page_range():
    page_string = '451-487'
    result = utils.split_page_artid(page_string)

    expected = '451', '487', None

    assert expected == result


def test_split_page_artid_page_start():
    page_string = '451'
    result = utils.split_page_artid(page_string)

    expected = '451', None, '451'

    assert expected == result


def test_split_page_artid_artid():
    page_string = 'CONF546'
    result = utils.split_page_artid(page_string)

    expected = None, None, 'CONF546'

    assert expected == result


def test_split_page_artid_unicode_dash():
    page_string = u'45−47'
    result = utils.split_page_artid(page_string)

    expected = '45', '47', None

    assert expected == result


def test_split_page_artid_long_page_start():
    page_string = 'B1234'
    result = utils.split_page_artid(page_string)

    expected = 'B1234', None, 'B1234'

    assert expected == result


def test_split_pubnote():
    pubnote = 'J.Testing,42,1-45'
    result = utils.split_pubnote(pubnote)

    expected = {
        'journal_title': 'J.Testing',
        'journal_volume': '42',
        'page_start': '1',
        'page_end': '45',
    }

    assert expected == result


def test_normalize_collaboration_preserves_valid_input():
    assert utils.normalize_collaboration('ATLAS') == ['ATLAS']


def test_normalize_collaboration_handles_none():
    assert utils.normalize_collaboration(None) == []


def test_normalize_collaboration_splits_on_and():
    assert utils.normalize_collaboration('ATLAS and CMS') == ['ATLAS', 'CMS']


def test_normalize_collaboration_removes_fluff():
    collaboration = 'for the ATLAS Collaboration'
    assert utils.normalize_collaboration(collaboration) == ['ATLAS']


def test_normalize_collaboration_splits_and_removes_fluff():
    collaboration = 'for the CMS and ATLAS Collaborations'
    assert utils.normalize_collaboration(collaboration) == ['CMS', 'ATLAS']


def test_normalize_collaboration_handles_parentheses():
    collaboration = '(ATLAS Collaboration)'
    assert utils.normalize_collaboration(collaboration) == ['ATLAS']


def test_normalize_collaboration_handles_parentheses():
    collaboration = '(for the CMS and ATLAS Collaborations)'
    assert utils.normalize_collaboration(collaboration) == ['CMS', 'ATLAS']


def test_get_license_from_url_handles_none():
    assert utils.get_license_from_url(None) is None


def test_get_license_from_url_raises_when_unknown_url():
    with pytest.raises(ValueError):
        utils.get_license_from_url('http://www.example.com')


def test_get_license_from_url_handles_CC():
    url = 'http://creativecommons.org/licenses/by-nc/4.0/'
    assert utils.get_license_from_url(url) == 'CC BY-NC 4.0'


def test_get_license_from_url_handles_arxiv():
    expected = 'arXiv nonexclusive-distrib 1.0'
    url = 'http://arxiv.org/licenses/nonexclusive-distrib/1.0/'
    assert utils.get_license_from_url(url) == expected


def test_convert_old_publication_info_to_new():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1214516',
            },
            'journal_title': 'Phys.Rev.',
            'journal_volume': 'C48',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Phys.Rev.C',
            'journal_volume': '48',
        },
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_journal_titles_not_ending_with_a_dot():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1214745',
            },
            'journal_title': 'Fizika',
            'journal_volume': 'B19',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Fizika B',
            'journal_volume': '19',
        },
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_journal_titles_with_already_a_letter():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1213787',
            },
            'journal_title': 'Kumamoto J.Sci.Ser.A',
            'journal_volume': '13',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1213787',
            },
            'journal_title': 'Kumamoto J.Sci.Ser.A',
            'journal_volume': '13',
        },
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_hidden_with_volume_variations():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1214521',
            },
            'journal_title': 'Phys.Lett.',
            'journal_volume': '72B',
        },
        {
            'hidden': True,
            'journal_title': 'Phys.Lett.',
            'journal_volume': 'B72',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Phys.Lett.B',
            'journal_volume': '72',
        },
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_hidden_without_volume_variations():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'artid': 'R10587',
            'journal_record': {
                '$ref': 'http://localhost:5000/api/journals/1214516',
            },
            'journal_title': 'Phys.Rev.',
            'journal_volume': 'B61',
        },
        {
            'artid': '10587',
            'hidden': True,
            'journal_title': 'Phys.Rev.',
            'journal_volume': 'B61',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'artid': 'R10587',
            'journal_title': 'Phys.Rev.B',
            'journal_volume': '61',
        },
        {
            'artid': '10587',
            'hidden': True,
            'journal_title': 'Phys.Rev.B',
            'journal_volume': '61',
        },
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_renamed_journals():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'artid': '525',
            'journal_title': 'Nucl.Phys.Proc.Suppl.',
            'journal_volume': '118',
            'page_start': '525',
        }
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'artid': '525',
            'journal_title': 'Nucl.Phys.B Proc.Suppl.',
            'journal_volume': '118',
            'page_start': '525',
        }
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_old_publication_info_to_new_handles_year_added_to_volumes():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'artid': '137',
            'journal_title': 'JHEP',
            'journal_volume': '1709',
            'year': 2017,
            'page_start': '137',
        }
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'artid': '137',
            'journal_title': 'JHEP',
            'journal_volume': '09',
            'year': 2017,
            'page_start': '137',
        }
    ]
    result = utils.convert_old_publication_info_to_new(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_new_publication_info_to_old():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_title': 'Phys.Rev.C',
            'journal_volume': '48',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Phys.Rev.',
            'journal_volume': 'C48',
        },
    ]
    result = utils.convert_new_publication_info_to_old(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_new_publication_info_to_old_handles_journals_with_already_a_letter():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_title': 'Kumamoto J.Sci.Ser.A',
            'journal_volume': '13',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Kumamoto J.Sci.Ser.A',
            'journal_volume': '13',
        },
    ]
    result = utils.convert_new_publication_info_to_old(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_new_publication_info_to_old_handles_phys_lett_b():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'journal_title': 'Phys.Lett.B',
            'journal_volume': '72',
        },
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'journal_title': 'Phys.Lett.',
            'journal_volume': '72B',
        },
        {
            'hidden': True,
            'journal_title': 'Phys.Lett.',
            'journal_volume': 'B72',
        },
    ]
    result = utils.convert_new_publication_info_to_old(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_new_publication_info_to_old_handles_renamed_journals():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'artid': '525',
            'journal_title': 'Nucl.Phys.B Proc.Suppl.',
            'journal_volume': '118',
            'page_start': '525',
        }
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'artid': '525',
            'journal_title': 'Nucl.Phys.Proc.Suppl.',
            'journal_volume': '118',
            'page_start': '525',
        }
    ]
    result = utils.convert_new_publication_info_to_old(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


def test_convert_new_publication_info_to_old_handles_year_added_to_volumes():
    schema = utils.load_schema('hep')
    subschema = schema['properties']['publication_info']

    publication_info = [
        {
            'artid': '137',
            'journal_title': 'JHEP',
            'journal_volume': '09',
            'year': 2017,
            'page_start': '137',
        }
    ]
    assert utils.validate(publication_info, subschema) is None

    expected = [
        {
            'artid': '137',
            'journal_title': 'JHEP',
            'journal_volume': '1709',
            'year': 2017,
            'page_start': '137',
        }
    ]
    result = utils.convert_new_publication_info_to_old(publication_info)

    assert utils.validate(result, subschema) is None
    assert expected == result


@pytest.mark.parametrize('uid,explicit_schema,expected_uid,expected_schema', [
    ('0000-0002-1825-0097', 'ORCID', '0000-0002-1825-0097', 'ORCID'),
    ('http://orcid.org/0000-0002-1825-0097', 'ORCID', '0000-0002-1825-0097', 'ORCID'),
    ('12345', 'CERN', 'CERN-12345', 'CERN'),
    ('A.Einstein.1', 'INSPIRE BAI', 'A.Einstein.1', 'INSPIRE BAI'),
    ('12345678', 'INSPIRE ID', 'INSPIRE-12345678', 'INSPIRE ID'),
    ('12345678', 'JACOW', 'JACoW-12345678', 'JACOW'),
    ('123456', 'SLAC', 'SLAC-123456', 'SLAC'),
    ('123456', 'DESY', 'DESY-123456', 'DESY'),
    ('0000-0002-1825-0097', None, '0000-0002-1825-0097', 'ORCID'),
    ('http://orcid.org/0000-0002-1825-0097', None, '0000-0002-1825-0097', 'ORCID'),
    ('CERN-12345', None, 'CERN-12345', 'CERN'),
    ('A.Einstein.1', None, 'A.Einstein.1', 'INSPIRE BAI'),
    ('INSPIRE-12345678', None, 'INSPIRE-12345678', 'INSPIRE ID'),
    ('JACoW-12345678', None, 'JACoW-12345678', 'JACOW'),
    ('SLAC-123456', None, 'SLAC-123456', 'SLAC'),
    ('DESY-123456', None, 'DESY-123456', 'DESY'),
])
def test_author_id_normalize_and_schema(
        uid, explicit_schema, expected_uid, expected_schema):
    normalized_uid, guessed_schema = utils.author_id_normalize_and_schema(uid, explicit_schema)
    assert guessed_schema == expected_schema
    assert normalized_uid == expected_uid


def test_author_id_normalize_and_schema_unknown():
    with pytest.raises(errors.UnknownUIDSchema):
        utils.author_id_normalize_and_schema('UNKNOWN-123', None)


def test_author_id_normalize_and_schema_conflict():
    with pytest.raises(errors.SchemaUIDConflict):
        utils.author_id_normalize_and_schema('SLAC-123456', 'CERN')


@pytest.mark.parametrize('arg1,arg2,source,material', [
    ('value', 'another', None, None),
    ('value', None, None, None),
    ('', [], None, None),
    (None, None, 'source', None),
    (None, None, None, 'material'),
])
def test_filter_empty_parameters(arg1, arg2, source, material):
    @utils.filter_empty_parameters
    def function_no_empty_args(arg1, arg2, source=None, material=None):
        if arg1 or arg2:
            return
        assert False

    function_no_empty_args(arg1, arg2, source=source, material=material)
