# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2019 CERN.
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

import pytest

from inspire_schemas.builders.jobs import JobBuilder


def test_no_data():
    expected = {"_collections": ["Jobs"], "status": "pending"}
    builder = JobBuilder()

    assert builder.record == expected


def test_data_in_init():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "some_key": "some_value",
        "some_key_with_list": ["some", "list"],
    }
    builder = JobBuilder(expected)

    assert builder.record == expected


def test_ensure_field_no_field():
    builder = JobBuilder()

    assert "test_field" not in builder.record

    builder._ensure_field("test_field", default_value="test_value")

    assert "test_field" in builder.record
    assert builder.record["test_field"] == "test_value"


def test_ensure_field_existing_field():
    builder = JobBuilder()

    assert "status" in builder.record

    builder._ensure_field("status", "other_status")

    assert builder.record["status"] == "pending"


def test_ensure_field_separate():
    builder = JobBuilder()
    obj = {"field_one": "value"}

    builder._ensure_field("test_field", default_value="test_value", obj=obj)
    builder._ensure_field("field_one", "wrong_value", obj=obj)

    assert "test_field" in obj
    assert obj["test_field"] == "test_value"
    assert obj["field_one"] == "value"


def test_ensure_list_field_missing():
    builder = JobBuilder()

    assert "list_field" not in builder.record

    builder._ensure_list_field("list_field")

    assert "list_field" in builder.record
    assert builder.record["list_field"] == []


def test_prepare_url():
    expected1 = {"value": "http://url1.com"}
    expected2 = {"description": "Url description", "value": "http://url2.com"}

    builder = JobBuilder()
    url1 = builder._prepare_url("http://url1.com")
    url2 = builder._prepare_url("http://url2.com", "Url description")
    with pytest.raises(TypeError):
        builder._prepare_url(description="only description")

    assert url1 == expected1
    assert url2 == expected2


def test_ensure_list_on_existing():
    builder = JobBuilder()

    builder._ensure_list_field("_collections")

    assert builder.record["_collections"] == ["Jobs"]


def test_ensure_dict_field_missing():
    builder = JobBuilder()
    builder.record["existing_dict"] = {"some_dict": "some_value"}

    assert "dict_field" not in builder.record

    builder._ensure_dict_field("dict_field")

    assert "dict_field" in builder.record
    assert builder.record["dict_field"] == {}


def test_ensure_dict_field_existing():
    builder = JobBuilder()
    builder.record["existing_dict"] = {"some_dict": "some_value"}

    builder._ensure_dict_field("existing_dict")

    assert builder.record["existing_dict"] == {"some_dict": "some_value"}


def test_sourced_dict_local_source():
    builder = JobBuilder(source="global")

    expected = {"source": "local", "value": "foo"}

    result = builder._sourced_dict("local", value="foo")

    assert result == expected


def test_sourced_dict_global_source():
    builder = JobBuilder(source="global")

    expected = {"source": "global", "value": "foo"}

    result = builder._sourced_dict(None, value="foo")

    assert result == expected


def test_sourced_dict_no_source():
    builder = JobBuilder()

    expected = {"value": "foo"}

    result = builder._sourced_dict(None, value="foo")

    assert result == expected


def test_append_to_field_some_simple_data():
    builder = JobBuilder()

    builder._append_to("test_field", "first_element")

    assert "test_field" in builder.record
    assert builder.record["test_field"] == ["first_element"]

    builder._append_to("test_field", "second_element")

    assert builder.record["test_field"] == ["first_element", "second_element"]


def test_append_to_field_duplicated_simple_data():
    builder = JobBuilder()

    builder._append_to("test_field", "first_element")
    builder._append_to("test_field", "second_element")
    builder._append_to("test_field", "first_element")
    builder._append_to("test_field", "second_element")

    assert builder.record["test_field"] == ["first_element", "second_element"]


def test_append_to_field_complex_data():
    element_one = {
        "key": "value",
        "list_key": ["some", "values"],
        "dict_key": {"key": "another_value", "something": "else"},
    }

    element_two = {
        "key": "value2",
        "other_list_key": ["some", "values"],
    }

    builder = JobBuilder()

    builder._append_to("some_field", element_one)
    assert builder.record["some_field"] == [element_one]

    builder._append_to("some_field", element_two)
    assert builder.record["some_field"] == [element_one, element_two]


def test_append_to_field_dumplicated_complex_data():
    element_one = {
        "key": "value",
        "list_key": ["some", "values"],
        "dict_key": {"key": "another_value", "something": "else"},
    }

    element_two = {
        "key": "value2",
        "other_list_key": ["some", "values"],
    }

    builder = JobBuilder()

    builder._append_to("some_field", element_one)
    builder._append_to("some_field", element_two)
    builder._append_to("some_field", element_one)
    builder._append_to("some_field", element_two)

    assert builder.record["some_field"] == [element_one, element_two]


def test_append_to_field_from_kwargs():
    element_one = {
        "key": "value",
        "list_key": ["some", "values"],
        "dict_key": {"key": "another_value", "something": "else"},
    }

    element_two = {
        "key": "value2",
        "other_list_key": ["some", "values"],
    }

    builder = JobBuilder()

    builder._append_to("some_field", **element_one)
    assert builder.record["some_field"] == [element_one]

    builder._append_to("some_field", element_two)
    assert builder.record["some_field"] == [element_one, element_two]


def test_add_private_note_with_source():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "_private_notes": [{"source": "http://some/source", "value": "Note"}],
    }
    builder = JobBuilder()

    builder.add_private_note("Note", "http://some/source")

    assert builder.record == expected


def test_add_private_note_without_source():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "_private_notes": [{"value": "Note"}],
    }
    builder = JobBuilder()

    builder.add_private_note("Note", "")

    assert builder.record == expected


def test_add_accelerator_experiment():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "accelerator_experiments": [
            {
                "accelerator": "accelerator",
                "curated_relation": False,
                "experiment": "test1",
                "institution": "test2",
                "legacy_name": "test3",
                "record": {"$ref": "http://something"},
            }
        ],
    }

    builder = JobBuilder()

    builder.add_accelerator_experiment(
        "accelerator", False, "test1", "test2", "test3", "http://something"
    )

    assert builder.record == expected


def test_add_acquisition_source():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "acquisition_source": {
            "source": "source",
            "submission_number": "12345",
            "datetime": "1999-02-01",
            "email": "email@email.com",
            "method": "method",
            "orcid": "orcid",
            "internal_uid": "uuid",
        },
    }

    expected2 = {
        "_collections": ["Jobs"],
        "status": "pending",
        "acquisition_source": {"submission_number": "None", "email": "blah@email.gov"},
    }

    builder = JobBuilder()

    builder.add_acquisition_source(
        "1999-02-01", "email@email.com", "uuid", "method", "orcid", "source", 12345
    )
    assert builder.record == expected

    builder.add_acquisition_source(email="blah@email.gov")

    assert builder.record == expected2


def test_add_arxiv_category():
    expected = {
        "_collections": ["Jobs"],
        "status": "pending",
        "arxiv_categories": ["cat1", "cat2"],
    }

    builder = JobBuilder()
    builder.add_arxiv_category("cat1")
    builder.add_arxiv_category("cat2")
    builder.add_arxiv_category("other")
    builder.add_arxiv_category("".join(list("other")))

    assert builder.record == expected


def test_add_contact():
    expected = [
        {
            "name": "name",
            "email": "email",
            "curated_relation": True,
            "record": {"$ref": "http://nothing"},
        },
        {"name": "name2", "email": "email2"},
        {
            "name": "name3",
        },
        {"email": "email3"},
    ]

    builder = JobBuilder()
    builder.add_contact(name="name", email="email", curated_relation=True, record="http://nothing")
    builder.add_contact(name="name2", email="email2")
    builder.add_contact(name="name3")
    builder.add_contact(email="email3")
    assert builder.record["contact_details"] == expected


def test_add_external_system_identifiers():
    expected = [
        {"schema": "schema1", "value": "value1"},
        {"schema": "schema2", "value": "value2"},
    ]

    builder = JobBuilder()

    builder.add_external_system_identifiers("value1", "schema1")
    builder.add_external_system_identifiers(schema="schema2", value="value2")
    with pytest.raises(TypeError):
        builder.add_external_system_identifiers("aaaaa")

    assert builder.record["external_system_identifiers"] == expected


def test_add_institution():
    expected = [
        {"value": "value", "curated_relation": False, "record": {"$ref": "http://xyz"}},
        {"value": "value2"},
    ]

    builder = JobBuilder()

    builder.add_institution(value="value", curated_relation=False, record={"$ref": "http://xyz"})
    builder.add_institution("value2")

    with pytest.raises(TypeError):
        builder.add_institution(record="blah")

    assert builder.record["institutions"] == expected


def test_add_rank():
    expected = ["Rank1", "Rank2"]

    builder = JobBuilder()
    builder.add_rank("Rank1")
    builder.add_rank("Rank2")

    assert builder.record["ranks"] == expected


def test_add_reference_emails():
    expected = {"emails": ["email@domain.xxx", "other@cern.ch"]}

    builder = JobBuilder()
    builder.add_reference_email("email@domain.xxx")
    builder.add_reference_email("other@cern.ch")
    builder.add_reference_email("")

    assert builder.record["reference_letters"] == expected


def test_reference_urls():
    expected = {
        "urls": [
            {"value": "http://some_url.ch"},
            {"value": "http://other.url.com", "description": "url description"},
        ]
    }

    builder = JobBuilder()

    builder.add_reference_url("http://some_url.ch")
    builder.add_reference_url("http://other.url.com", "url description")
    builder.add_reference_url("")

    assert builder.record["reference_letters"] == expected


def test_add_reference_both():
    expected = {
        "emails": ["poczta@domena.pl", "postane@domain.tr"],
        "urls": [
            {"value": "https://jakas_strona.pl"},
            {"value": "http://xyz.uk", "description": "Some description"},
        ],
    }

    builder = JobBuilder()

    builder.add_reference_email("poczta@domena.pl")
    builder.add_reference_email("postane@domain.tr")

    builder.add_reference_url("https://jakas_strona.pl")
    builder.add_reference_url("http://xyz.uk", "Some description")

    assert builder.record["reference_letters"] == expected


def test_add_region():
    expected = ["Region1", "Region2"]

    builder = JobBuilder()

    builder.add_region("Region1")
    builder.add_region("Region2")

    assert builder.record["regions"] == expected


def test_add_url():
    expected = [
        {"value": "http://url.com"},
        {"value": "https://url2.ch", "description": "Description for this url"},
    ]

    builder = JobBuilder()

    builder.add_url("http://url.com")
    builder.add_url("https://url2.ch", "Description for this url")

    with pytest.raises(TypeError):
        builder.add_url(description="some description")

    assert builder.record["urls"] == expected


def test_set_deadline():
    expected1 = "2099-02-15"
    expected2 = "1099-09-20"

    builder = JobBuilder()

    builder.set_deadline(expected1)
    assert builder.record["deadline_date"] == expected1

    builder.set_deadline(expected2)
    assert builder.record["deadline_date"] == expected2


def test_set_external_job_identifier():
    expected1 = "Identifier1"
    expected2 = "Other Identifier"

    builder = JobBuilder()

    builder.set_external_job_identifier(expected1)
    assert builder.record["external_job_identifier"] == expected1

    builder.set_external_job_identifier(expected2)
    assert builder.record["external_job_identifier"] == expected2


def test_set_description():
    def test_set_deadline():
        expected1 = "Description"
        expected2 = "Other Description"

        builder = JobBuilder()

        builder.set_description(expected1)
        assert builder.record["description"] == expected1

        builder.set_description(expected2)
        assert builder.record["description"] == expected2


def test_set_status():
    expected1 = "pending"
    expected2 = "closed"

    builder = JobBuilder()

    builder.set_status(expected1)
    assert builder.record["status"] == expected1

    builder.set_status(expected2)
    assert builder.record["status"] == expected2


def test_set_title():
    expected1 = "TITLE1"
    expected2 = "TITLE2"

    builder = JobBuilder()

    builder.set_title(expected1)
    assert builder.record["position"] == expected1

    builder.set_title(expected2)
    assert builder.record["position"] == expected2


def test_process_reference_contact_list():
    contacts = [
        "some.email@cern.ch",
        "http://some-url.com/other/?url=1&part=2",
        "other@email.com",
    ]

    builder = JobBuilder()
    builder.add_reference_contacts(contacts)

    expected_data = {
        "emails": ["some.email@cern.ch", "other@email.com"],
        "urls": [{"value": "http://some-url.com/other/?url=1&part=2"}],
    }

    assert builder.record["reference_letters"] == expected_data


def test_sanitization_of_description():
    expected = (
        '<div>Some text <em>emphasized</em> linking to <a href="http://example.com">'
        "http://example.com</a></div>"
    )
    description = (
        '<div>Some <span>text</span> <em class="shiny">emphasized</em> linking to '
        "http://example.com</div>"
    )
    builder = JobBuilder()
    builder.set_description(description)

    assert builder.record["description"] == expected
