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

from inspire_schemas.parsers.jats import JatsParser
from inspire_schemas.utils import validate


def get_parsed_from_file(filename):
    """A dictionary holding the parsed elements of the record."""
    path = get_test_suite_path("aps", filename)
    with open(path) as f:
        aps_expected_dict = yaml.full_load(f)

    return aps_expected_dict


def get_parser_by_file(filename):
    """A JatsParser instanciated on an APS article."""
    path = get_test_suite_path("aps", filename)
    with open(path) as f:
        aps_jats = f.read()

    return JatsParser(aps_jats)


@pytest.fixture(
    scope="module",
    params=[
        ("PhysRevD.102.014505.xml", "PhysRevD.102.014505_expected.yml"),
        ("PhysRevX.7.021022.xml", "PhysRevX.7.021022_expected.yml"),
        ("PhysRevX.4.021018.xml", "PhysRevX.4.021018_expected.yml"),
        ("PhysRevD.96.095036.xml", "PhysRevD.96.095036_expected.yml"),
        ("PhysRevX.7.021021.xml", "PhysRevX.7.021021_expected.yml"),
    ],
)
def records(request):
    return {
        "jats": get_parser_by_file(request.param[0]),
        "expected": get_parsed_from_file(request.param[1]),
        "file_name": request.param[0],
    }


FIELDS_TO_CHECK = [
    "abstract",
    "copyright_holder",
    "copyright_statement",
    "copyright_year",
    "document_type",
    "license_url",
    "license_statement",
    "article_type",
    "journal_title",
    "material",
    "publisher",
    "year",
    "authors",
    "artid",
    "title",
    "number_of_pages",
    "dois",
    "references",
    "journal_volume",
    "journal_issue",
    "is_conference_paper",
]
FIELDS_TO_CHECK_SEPARATELY = [
    "publication_date",
    "documents",
]


def test_data_completeness(records):
    tested_fields = FIELDS_TO_CHECK + FIELDS_TO_CHECK_SEPARATELY
    for field in records["expected"]:
        assert field in tested_fields


@pytest.mark.parametrize("field_name", FIELDS_TO_CHECK)
def test_field(field_name, records):
    result = getattr(records["jats"], field_name)
    expected = records["expected"][field_name]

    if field_name == "authors":
        diffs = DeepDiff(result, expected, ignore_order=True)
        if sys.version_info[0] < 3 and "type_changes" in diffs:
            del diffs["type_changes"]
        assert diffs == {}
    else:
        assert result == expected


def test_publication_date(records):
    result = records["jats"].publication_date.dumps()
    expected = records["expected"]["publication_date"].isoformat()

    assert result == expected


@pytest.mark.skip(reason="No collaboration in input")
def test_collaborations(records):
    result = records["jats"].collaborations
    expected = records["expected"]["collaborations"]

    assert result == expected


def test_parse(records):
    record = records["jats"].parse()
    assert validate(record, "hep") is None


def test_attach_fulltext_document(records):
    parser = records["jats"]
    parser.attach_fulltext_document(
        records["file_name"], "http://example.org/{}".format(records["file_name"])
    )
    result = parser.parse()

    assert result["documents"] == records["expected"]["documents"]


def test_journal_title_physcis_is_converted_to_aps_physics():
    parser = get_parser_by_file("Physics.15.168.xml")
    result = parser.parse()
    assert result["publication_info"][0]["journal_title"] == "APS Physics"
