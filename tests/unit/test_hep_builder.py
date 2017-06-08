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

from inspire_schemas.builders import LiteratureBuilder, is_citeable


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
