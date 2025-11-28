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

import io

import six
from fixtures import get_test_suite_path

from inspire_schemas.parsers.author_xml import AuthorXMLParser


def get_parser_by_file(filename):
    """A ArxivParser instanciated on an APS article."""
    path = get_test_suite_path("arxiv", filename)
    with io.open(path, encoding="utf-8") as f:
        arxiv_content = six.ensure_text(f.read())

    return AuthorXMLParser(arxiv_content)


def test_parsing_author_xml():
    data = """
    <collaborationauthorlist xmlns:foaf="http://xmlns.com/foaf/0.1/" xmlns:cal="http://inspirehep.net/info/HepNames/tools/authors_xml/">
    <cal:creationDate>2022-01-25</cal:creationDate>
    <cal:publicationReference>Fermilab-PUB-2022-01-25</cal:publicationReference>
    <cal:collaborations>
    <cal:collaboration id="duneid">
    <foaf:name>DUNE</foaf:name>
    <cal:experimentNumber>DUNE</cal:experimentNumber>
    </cal:collaboration>
    </cal:collaborations>
    <cal:authors>
        <foaf:Person>
            <foaf:name>Michael Finger</foaf:name>
            <foaf:givenName>Michael</foaf:givenName>
            <foaf:familyName>Finger</foaf:familyName>
            <cal:authorNameNative lang=""/>
            <cal:authorSuffix>Jr.</cal:authorSuffix>
            <cal:authorStatus/>
            <cal:authorNamePaper>M. Finger Jr.</cal:authorNamePaper>
            <cal:authorAffiliations>
            <cal:authorAffiliation organizationid="o27" connection=""/>
            <cal:authorAffiliation organizationid="vo1" connection="AlsoAt"/>
            </cal:authorAffiliations>
            <cal:authorIDs>
            <cal:authorID source="INSPIRE">INSPIRE-00171357</cal:authorID>
            <cal:authorID source="CCID">391883</cal:authorID>
            <cal:authorID source="ORCID">0000-0003-3155-2484</cal:authorID>
            </cal:authorIDs>
        </foaf:Person>
    </cal:authors>
    </collaborationauthorlist>
    """
    result = AuthorXMLParser(data).parse()
    assert result[0]["full_name"] == "Finger, Michael, Jr."


def test_arxiv_handles_non_ascii_organization_names():
    parser = get_parser_by_file("B2G-20-002-authorlist.xml")
    result = parser.parse()
    assert len(result) > 0


def test_arxiv_handles_newLines():
    parser = get_parser_by_file("BAM494_author.xml")
    result = parser.parse()
    expected_author = [
        {
            "affiliations": [
                {"value": "Beijing, Inst. High Energy Phys."},
            ],
            "ids": [
                {"value": "INSPIRE-00059665", "schema": "INSPIRE ID"},
                {"value": "0000-0002-3935-619X", "schema": "ORCID"},
            ],
            "full_name": "Ablikim, Medina",
        },
    ]

    assert expected_author[0] == result[0]


def test_arxiv_author_list_handles_auto_ignore_comment():
    parser = get_parser_by_file("EXO-15-009-authorlist.xml")
    result = parser.parse()

    expected_authors = [
        {
            "affiliations": [{"value": "Yerevan Phys. Inst."}],
            "ids": [
                {"value": "INSPIRE-00312131", "schema": "INSPIRE ID"},
                {"value": "CERN-432142", "schema": "CERN"},
            ],
            "full_name": "Sirunyan, Albert M.",
        },
    ]

    assert result == expected_authors


def test_arxiv_author_test_identifiers():
    parser = get_parser_by_file("atlas_authlist.xml")
    result = parser.parse()

    expected_authors = [
        {
            "affiliations": [{"value": "Marseille, CPPM"}],
            "ids": [
                {"value": "INSPIRE-00210391", "schema": "INSPIRE ID"},
                {"value": "0000-0002-6665-4934", "schema": "ORCID"},
            ],
            "full_name": "Aad, Georges",
            "affiliations_identifiers": [
                {"value": "https://ror.org/00fw8bp86", "schema": "ROR"},
                {"value": "grid.470046.1", "schema": "GRID"},
            ],
        },
        {
            "affiliations": [{"value": "Oklahoma U."}],
            "ids": [
                {"value": "INSPIRE-00060668", "schema": "INSPIRE ID"},
                {"value": "0000-0002-5888-2734", "schema": "ORCID"},
            ],
            "full_name": "Abbott, Braden Keim",
            "affiliations_identifiers": [
                {"value": "https://ror.org/02aqsxs83", "schema": "ROR"},
                {"value": "grid.266900.b", "schema": "GRID"},
            ],
        },
    ]
    assert expected_authors[0] == result[0]
    assert expected_authors[1] == result[1]


def test_arxiv_author_test_institutional_namespace():
    parser = get_parser_by_file("export_xml_authors_2022-01-25.xml")
    result = parser.parse()

    expected_authors = [
        {
            "affiliations": [{"value": "Liverpool U."}, {"value": "CERN"}],
            "ids": [
                {"value": "INSPIRE-00657132", "schema": "INSPIRE ID"},
            ],
            "full_name": "Abed Abud, Adam",
        },
        {
            "affiliations": [{"value": "Oxford U."}],
            "ids": [
                {"value": "0000-0001-7036-9645", "schema": "ORCID"},
                {"value": "INSPIRE-00210439", "schema": "INSPIRE ID"},
            ],
            "full_name": "Abi, Babak",
        },
    ]

    assert expected_authors[0] == result[0]
    assert expected_authors[1] == result[1]


def test_arxiv_author_no_none_in_institution_affiliations():
    parser = get_parser_by_file("export_xml_authors_2022-01-25.xml")
    result = parser.parse()
    expected_authors = [
        {
            "affiliations": [
                {"value": "INFN, Catania"},
            ],
            "ids": [
                {"value": "INSPIRE-00700856", "schema": "INSPIRE ID"},
            ],
            "full_name": "Ali-Mohammadzadeh, Behnam",
        },
    ]

    assert expected_authors[0] == result[14]


def test_arxiv_author_no_organization_name():
    parser = get_parser_by_file("arxiv_authorlist.xml")
    result = parser.parse()

    expected_authors = [
        {
            "ids": [
                {"value": "INSPIRE-00149777", "schema": "INSPIRE ID"},
            ],
            "full_name": "Biermann, Peter",
        },
    ]

    assert expected_authors[0] == result[29]


def test_arxiv_handles_invalid_authorid_value():
    parser = get_parser_by_file("2021-07-13-Alice_Authorlist_2021-07-13.xml")
    result = parser.parse()

    expected_authors = [
        {
            "affiliations": [
                {"value": "Kosice U."},
            ],
            "affiliations_identifiers": [
                {"value": "https://ror.org/039965637", "schema": "ROR"},
            ],
            "full_name": "Ahuja, Ishaan",
        },
    ]

    assert expected_authors[0] == result[9]


def test_arxiv_handles_non_ascii_affiliations():
    parser = get_parser_by_file("authors.xml")
    result = parser.parse()

    expected_authors = [
        {
            "affiliations": [
                {"value": "Liverpool U."},
                {"value": "CERN"},
            ],
            "ids": [
                {"value": "INSPIRE-00657132", "schema": "INSPIRE ID"},
            ],
            "affiliations_identifiers": [
                {"value": "https://ror.org/04xs57h96", "schema": "ROR"},
                {"value": "https://ror.org/01ggx4157", "schema": "ROR"},
            ],
            "full_name": "Abed Abud, Adam",
        },
    ]

    assert expected_authors[0] == result[0]


def test_arxiv_author_no_none_in_ror():
    parser = get_parser_by_file("authors.xml")
    result = parser.parse()
    expected_author = [
        {
            "affiliations": [
                {"value": "INFN, Catania"},
            ],
            "ids": [
                {"value": "INSPIRE-00700856", "schema": "INSPIRE ID"},
            ],
            "affiliations_identifiers": [
                {"value": "https://ror.org/02pq29p90", "schema": "ROR"},
            ],
            "full_name": "Ali-Mohammadzadeh, Behnam",
        },
    ]

    assert expected_author[0] == result[16]
