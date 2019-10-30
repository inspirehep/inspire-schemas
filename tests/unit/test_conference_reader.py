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
from inspire_schemas.readers.conference import ConferenceReader


def test_city():
    schema = load_schema('conferences')
    subschema = schema['properties']['addresses']

    record = {
        'addresses': [
            {
                'cities': [
                    'Tokyo',
                ],
            },
        ],
    }
    assert validate(record['addresses'], subschema) is None

    expected = 'Tokyo'
    result = ConferenceReader(record).city

    assert expected == result


def test_city_when_no_city_in_first_address():
    schema = load_schema('conferences')
    subschema = schema['properties']['addresses']

    record = {
        'addresses': [
            {
                'place_name': 'Lido di Venezia',
            },
            {
                'cities': [
                    'Venice',
                ],
            },
        ],
    }
    assert validate(record['addresses'], subschema) is None

    expected = 'Venice'
    result = ConferenceReader(record).city

    assert expected == result


def test_country():
    schema = load_schema('conferences')
    subschema = schema['properties']['addresses']

    record = {
        'addresses': [
            {'country_code': 'JP'},
        ],
    }
    assert validate(record['addresses'], subschema) is None

    expected = 'jp'
    result = ConferenceReader(record).country

    assert expected == result


def test_get_conference_end_date():
    schema = load_schema('conferences')
    subschema = schema['properties']['closing_date']

    record = {'closing_date': '1999-11-19'}
    assert validate(record['closing_date'], subschema) is None

    expected = '1999-11-19'
    result = ConferenceReader(record).end_date

    assert expected == result


def test_conference_start_date():
    schema = load_schema('conferences')
    subschema = schema['properties']['opening_date']

    record = {'opening_date': '1999-11-16'}
    assert validate(record['opening_date'], subschema) is None

    expected = '1999-11-16'
    result = ConferenceReader(record).start_date

    assert expected == result
