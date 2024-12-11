# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2014-2024 CERN.
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

from __future__ import (
    absolute_import,
    division,
    print_function,
)

import sys

import pytest
import yaml
from deepdiff import DeepDiff
from fixtures import get_test_suite_path

from inspire_schemas.parsers.elsevier import ElsevierParser
from inspire_schemas.utils import validate


def get_parsed_from_file(filename):
    """A dictionary holding the parsed elements of the record."""
    path = get_test_suite_path('elsevier', filename)
    with open(path) as f:
        elsevier_expected_dict = yaml.load(f)

    return elsevier_expected_dict


def get_parser_by_file(filename):
    """A ElsevierParser instanciated on an APS article."""
    path = get_test_suite_path('elsevier', filename)
    with open(path) as f:
        aps_elsevier = f.read()

    return ElsevierParser(aps_elsevier)


@pytest.fixture(
    scope='module',
    params=[
        ('j.nima.2019.162787.xml', 'j.nima.2019.162787_expected.yml'),
        ('j.nuclphysa.2020.121991.xml', 'j.nuclphysa.2020.121991_expected.yml'),
        ('j.nima.2019.162728.xml', 'j.nima.2019.162728_expected.yml'),
        ('j.nimb.2019.04.063.xml', 'j.nimb.2019.04.063_expected.yml'),
        ('j.cpc.2020.107740.xml', 'j.cpc.2020.107740_expected.yml'),
        ('j.scib.2020.01.008.xml', 'j.scib.2020.01.008_expected.yml'),
        ('aphy.2001.6176.xml', 'aphy.2001.6176_expected.yml'),
        ('j.aim.2021.107831.xml', 'j.aim.2021.107831_expected.yml'),
        ('j.nuclphysa.2020.121992.xml', 'j.nuclphysa.2020.121992_expected.yml'),
    ],
)
def records(request):
    return {
        'elsevier': get_parser_by_file(request.param[0]),
        'expected': get_parsed_from_file(request.param[1]),
        'file_name': request.param[0],
    }


FIELDS_TO_CHECK = [
    'abstract',
    'copyright_holder',
    'copyright_statement',
    'copyright_year',
    'document_type',
    'license_url',
    'license_statement',
    'keywords',
    'article_type',
    'journal_title',
    'material',
    'publisher',
    'year',
    'authors',
    'artid',
    'title',
    'dois',
    'references',
    'journal_volume',
    'journal_issue',
    'is_conference_paper',
]
FIELDS_TO_CHECK_SEPARATELY = ['publication_date', 'documents', 'collaborations']


def test_data_completeness(records):
    tested_fields = FIELDS_TO_CHECK + FIELDS_TO_CHECK_SEPARATELY
    for field in records['expected']:
        assert field in tested_fields


@pytest.mark.parametrize('field_name', FIELDS_TO_CHECK)
def test_field(field_name, records):
    result = getattr(records['elsevier'], field_name)
    expected = records['expected'][field_name]
    if field_name == 'authors':
        diffs = DeepDiff(result, expected, ignore_order=True)
        if sys.version_info[0] < 3 and 'type_changes' in diffs:
            del diffs['type_changes']
        assert diffs == {}
    else:
        assert result == expected


def test_publication_date(records):
    result = records['elsevier'].publication_date.dumps()
    expected = records['expected']['publication_date']

    assert result == expected


def test_collaborations(records):
    result = records['elsevier'].collaborations
    expected = records['expected']['collaborations']

    assert result == expected


def test_parse(records):
    record = records['elsevier'].parse()
    assert validate(record, 'hep') is None


def test_attach_fulltext_document(records):
    parser = records['elsevier']
    parser.attach_fulltext_document(
        records['file_name'], 'http://example.org/{}'.format(records['file_name'])
    )
    result = parser.parse()
    assert result['documents'] == records['expected']['documents']


def test_get_identifier(records):
    parser = records['elsevier']
    result_doi = parser.get_identifier()
    assert result_doi == records['expected']['dois'][0]['doi']


def test_record_should_be_harvested(records):
    parser = records['elsevier']
    assert parser.should_record_be_harvested()


def test_record_shouldnt_be_harvested():
    parser = get_parser_by_file("record-that-shouldnt-be-harvested.xml")
    assert not parser.should_record_be_harvested()


def test_imprints_date_should_be_taken_from_avaliable_online():
    parser = get_parser_by_file("j.nima.2023.168018.xml")
    result = parser.parse()
    assert result['imprints'] == [{'date': '2023-01-02'}]
