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

import contextlib
import json
import os

import mock
import pytest
import six

from inspire_schemas import errors, utils


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
        def __init__(self): pass

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
        def __init__(self): pass

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
        lambda x: 'And his nostrils ripped and his bottom burned off'

    loaded_schema = utils.load_schema('And gallantly he chickened out')

    assert loaded_schema == myschema


@mock.patch('inspire_schemas.utils.open')
@mock.patch('inspire_schemas.utils.get_schema_path')
def test_load_schema_without_schema_key(mock_get_schema_path, mock_open):
    myschema = {
        'Sir Robin': 'The fleeing brave',
    }
    mock_open.side_effect = \
        lambda x: contextlib.closing(six.StringIO(json.dumps(myschema)))
    mock_get_schema_path.side_effect = \
        lambda x: 'And his nostrils ripped and his bottom burned off'

    loaded_schema = utils.load_schema('And gallantly he chickened out')

    assert loaded_schema == {'$schema': myschema}


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


def test_split_pubnote():
    pubnote = 'J.Testing,42,1-45'
    result = utils.split_pubnote(pubnote)

    expected = 'J.Testing', '42', '1', '45', None

    assert expected == result


def test_normalize_author_name_with_comma_with_spaces():
    name1 = 'Smith, J P '

    result1 = utils.normalize_author_name_with_comma(name1)

    expected1 = 'Smith, J.P.'

    assert expected1 == result1

    name2 = 'Smith, J P'

    result2 = utils.normalize_author_name_with_comma(name2)

    expected2 = 'Smith, J.P.'

    assert expected2 == result2


def test_normalize_author_name_full():
    name = 'Smith, John Peter'

    result = utils.normalize_author_name_with_comma(name)

    expected = 'Smith, John Peter'

    assert expected == result


def test_normalize_author_name_with_comma_with_dots():
    name1 = 'Smith, J. P.'

    result1 = utils.normalize_author_name_with_comma(name1)

    expected1 = 'Smith, J.P.'

    assert expected1 == result1

    name2 = 'Smith, J.P.'

    result2 = utils.normalize_author_name_with_comma(name2)

    expected2 = 'Smith, J.P.'

    assert expected2 == result2

    name3 = 'Smith, J.P. '

    result3 = utils.normalize_author_name_with_comma(name3)

    expected3 = 'Smith, J.P.'

    assert expected3 == result3

    name4 = 'Smith, J. P. '

    result4 = utils.normalize_author_name_with_comma(name4)

    expected4 = 'Smith, J.P.'

    assert expected4 == result4
