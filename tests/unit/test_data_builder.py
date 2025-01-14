# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016, 2019, 2024 CERN.
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

from inspire_schemas.builders.data import DataBuilder


def test_append_to():
    formdata = ''
    builder = DataBuilder("test")
    expected_result = None
    builder._append_to('test_field', formdata)
    assert builder.record.get('test_field') is expected_result
    formdata = 'value'
    expected_result = ['value']
    builder._append_to('test_field_2', formdata)
    assert builder.record.get('test_field_2') == expected_result


def test_add_abstract():
    builder = DataBuilder()
    abstract = "This is a test abstract."
    source = "Test Source"
    builder.add_abstract(abstract, source)
    builder.validate_record()
    result = builder.record.get("abstracts")
    expected = [{"source": source, "value": abstract}]
    assert result == expected


def test_add_author():
    builder = DataBuilder()
    author_data = {
        "full_name": "Smith, John",
        "affiliations": [{"value": "CERN"}],
        "emails": ["john.smith@example.org"],
    }
    builder.add_author(author_data)
    builder.validate_record()
    result = builder.record.get("authors")
    expected = [author_data]
    assert result == expected


def test_add_title():
    builder = DataBuilder()
    title = "A Great Title"
    subtitle = "An Even Better Subtitle"
    source = "Test Source"
    builder.add_title(title, subtitle, source)
    builder.validate_record()
    result = builder.record.get("titles")
    expected = [
        {"source": source, "title": title, "subtitle": subtitle},
    ]
    assert result == expected

def test_add_creation_date():
    builder = DataBuilder()
    creation_date = "2020-01-01"
    builder.add_creation_date(creation_date)
    builder.validate_record()
    result = builder.record.get("creation_date")
    assert result == creation_date

def test_add_doi():
    builder = DataBuilder()
    doi = "10.1234/example.doi"
    source = "Test Source"
    builder.add_doi(doi, source)
    builder.validate_record()
    result = builder.record.get("dois")
    expected = [{"source": source, "value": "10.1234/example.doi"}]
    assert result == expected


def test_add_keyword():
    builder = DataBuilder()
    keyword = "Physics"
    source = "Test Source"
    builder.add_keyword(keyword, source)
    builder.validate_record()
    result = builder.record.get("keywords")
    expected = [{"source": source, "value": keyword}]
    assert result == expected


def test_add_accelerator_experiment():
    builder = DataBuilder()
    legacy_name = "FNAL-E-0900"
    experiment_record = {"$ref": "http://example.com/api/experiments/123"}
    builder.add_accelerator_experiment(legacy_name, record=experiment_record)
    builder.validate_record()
    result = builder.record.get("accelerator_experiments")
    expected = [{"legacy_name": legacy_name, "record": experiment_record}]
    assert result == expected


def test_add_literature():
    builder = DataBuilder()

    doi = "10.1234/example.doi"
    record = {"$ref": "http://example.com/api/literature/123"}
    source = "testsource"

    builder.add_literature(doi, record=record, source=source)
    builder.validate_record()

    result = builder.record.get("literature")
    expected = [
        {
            "doi":{
                "source": "testsource",
                "value":"10.1234/example.doi"
            },
            "record":{
                "$ref":"http://example.com/api/literature/123"
            }
        }
    ]

    assert result == expected
