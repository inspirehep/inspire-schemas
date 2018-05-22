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

from inspire_schemas.api import load_schema, validate
from inspire_schemas.builders.authors import AuthorBuilder


def test_author_builder_default_constructor():
    expected = {}
    result = AuthorBuilder()

    assert expected == result.obj


def test_author_builder_copy_constructor():
    expected = {'name': {'value': 'Torre, Riccardo'}}
    result = AuthorBuilder({'name': {'value': 'Torre, Riccardo'}})

    assert expected == result.obj


def test_author_builder_set_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_author_builder_set_name_normalizes_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Riccardo Torre')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_author_builder_set_name_can_be_called_multiple_times():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Richard Tower')
    author.set_name('Riccardo Torre')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result
