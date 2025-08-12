# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2024 CERN.
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

import pytest

from inspire_schemas.parsers.hepdata import HEPDataParser


@pytest.fixture
def sample_hepdata_payload():
    """Sample HEPData payload for testing."""
    return {
        "base": {
            "record": {
                "collaborations": ["CMS"],
                "data_abstract": "This is a test abstract for data analysis.",
                "data_keywords": {
                    "cmenergies": [{"lte": "13000", "gte": "8000"}],
                    "observables": ["cross_section", "efficiency"],
                    "other_keyword": ["value1", "value2"],
                },
                "creation_date": "2024-01-01",
                "last_updated": "2024-01-15",
                "doi": "10.1000/182",
                "inspire_id": "12345",
                "resources": [
                    {
                        "url": "https://example.com/data.root",
                        "description": "ROOT file with analysis data",
                    },
                    {
                        "url": "https://www.hepdata.net/record/resource/123",
                        "description": "Internal HEPData resource",
                    },
                ],
                "title": "Test Data Record",
                "hepdata_doi": "10.17182/hepdata.12345.v1",
            }
        },
        "1": {
            "record": {
                "creation_date": "2024-01-01",
                "last_updated": "2024-01-15",
                "hepdata_doi": "10.17182/hepdata.12345.v1",
            },
            "data_tables": [{"doi": "10.17182/hepdata.12345.v1/t1"}],
            "resources_with_doi": [{"doi": "10.17182/hepdata.12345.v1/r1"}],
        },
    }


def test_hepdata_parser_initialization():
    """Test HEPData parser initialization."""
    payload = {"base": {"record": {}}}
    inspire_url = "https://inspirehep.net"

    parser = HEPDataParser(payload, inspire_url)

    assert parser.payload == payload
    assert parser.inspire_url == inspire_url
    assert parser.source == "HEPData"
    assert parser.builder is not None


def test_hepdata_parser_custom_source():
    """Test HEPData parser with custom source."""
    payload = {"base": {"record": {}}}
    inspire_url = "https://inspirehep.net"
    custom_source = "CustomSource"

    parser = HEPDataParser(payload, inspire_url, source=custom_source)

    assert parser.source == custom_source


def test_hepdata_parser_parse(sample_hepdata_payload):
    """Test full parsing of HEPData payload."""
    inspire_url = "https://inspirehep.net"
    parser = HEPDataParser(sample_hepdata_payload, inspire_url)

    result = parser.parse()
    assert "_collections" in result
    assert "Data" in result["_collections"]
    assert "collaborations" in result
    assert result["collaborations"][0]["value"] == "CMS"
    assert "abstracts" in result
    assert result["abstracts"][0]["value"] == "This is a test abstract for data analysis."
    assert "titles" in result
    assert result["titles"][0]["title"] == "Test Data Record"
    assert "creation_date" in result
    assert result["creation_date"] == "2024-01-15"
    assert "literature" in result
    literature = result["literature"][0]
    assert literature["record"]["$ref"] == "https://inspirehep.net/api/literature/12345"
    assert literature["doi"]["value"] == "10.1000/182"
    assert "keywords" in result
    keyword_values = [kw["value"] for kw in result["keywords"]]
    assert "cmenergies: 13000-8000" in keyword_values
    assert "observables: cross_section" in keyword_values
    assert "observables: efficiency" in keyword_values
    assert "value1" in keyword_values
    assert "value2" in keyword_values
    assert "urls" in result
    urls = [url["value"] for url in result["urls"]]
    assert "https://example.com/data.root" in urls
    assert "https://www.hepdata.net/record/resource/123" not in urls
    assert "dois" in result
    doi_values = [(doi["value"], doi["material"]) for doi in result["dois"]]
    assert ("10.17182/hepdata.12345", "data") in doi_values
    assert ("10.17182/hepdata.12345.v1", "version") in doi_values
    assert ("10.17182/hepdata.12345.v1/t1", "part") in doi_values
    assert ("10.17182/hepdata.12345.v1/r1", "part") in doi_values
    assert "acquisition_source" in result
    acq_source = result["acquisition_source"]
    assert acq_source["method"] == "inspirehep"
    assert acq_source["submission_number"] == "12345"
    assert "datetime" in acq_source


def test_add_keywords_cmenergies(sample_hepdata_payload):
    """Test keyword handling for cmenergies."""
    inspire_url = "https://inspirehep.net"
    parser = HEPDataParser(sample_hepdata_payload, inspire_url)

    parser._add_keywords(sample_hepdata_payload["base"]["record"])

    keywords = [kw["value"] for kw in parser.builder.record.get("keywords", [])]
    assert "cmenergies: 13000-8000" in keywords


def test_add_date_with_last_updated(sample_hepdata_payload):
    """Test date handling with last_updated."""
    inspire_url = "https://inspirehep.net"
    parser = HEPDataParser(sample_hepdata_payload, inspire_url)

    parser._add_date(sample_hepdata_payload["1"]["record"])

    assert parser.builder.record["creation_date"] == "2024-01-15"


def test_add_date_without_last_updated():
    """Test date handling without last_updated."""
    record = {"creation_date": "2024-01-01"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_date(record)

    assert parser.builder.record["creation_date"] == "2024-01-01"


def test_add_date_with_dummy_last_updated():
    """Test date handling with dummy last_updated date."""
    record = {"creation_date": "2024-01-01", "last_updated": "1970-01-01"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_date(record)

    assert parser.builder.record["creation_date"] == "2024-01-01"


def test_add_literature_with_doi():
    """Test literature reference with DOI."""
    record = {"doi": "10.1000/182", "inspire_id": "12345"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_literature_reference(record)

    literature = parser.builder.record["literature"][0]
    assert literature["record"]["$ref"] == "https://inspirehep.net/api/literature/12345"
    assert literature["doi"]["value"] == "10.1000/182"


def test_add_literature_without_doi():
    """Test literature reference without DOI."""
    record = {"inspire_id": "12345"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_literature_reference(record)

    literature = parser.builder.record["literature"][0]
    assert literature["record"]["$ref"] == "https://inspirehep.net/api/literature/12345"
    assert "doi" not in literature


def test_add_dois_with_version():
    """Test DOI handling with version pattern."""
    record = {"hepdata_doi": "10.17182/hepdata.12345.v1"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_dois(record)

    dois = parser.builder.record["dois"]
    assert len(dois) == 1
    assert dois[0]["value"] == "10.17182/hepdata.12345"
    assert dois[0]["material"] == "data"


def test_add_dois_without_version():
    """Test DOI handling without version pattern."""
    record = {"hepdata_doi": "10.17182/hepdata.12345"}
    inspire_url = "https://inspirehep.net"
    payload = {"base": {"record": {}}}
    parser = HEPDataParser(payload, inspire_url)

    parser._add_dois(record)

    dois = parser.builder.record["dois"]
    assert len(dois) == 1
    assert dois[0]["value"] == "10.17182/hepdata.12345"
    assert dois[0]["material"] == "data"
