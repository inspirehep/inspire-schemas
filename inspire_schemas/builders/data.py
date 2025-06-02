# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2017, 2024 CERN.
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

"""Data builder class and related code."""

from __future__ import absolute_import, division, print_function

import warnings

from idutils import normalize_doi
from inspire_utils.date import normalize_date
from six import python_2_unicode_compatible, text_type

from inspire_schemas.builders.builder import RecordBuilder
from inspire_schemas.utils import (
    filter_empty_parameters,
    validate,
)


def is_citeable():
    # TODO Implement this function
    return False


def key_already_there(element, elements):
    """Checks if the given element existng by using the key `key`."""
    return any(element["key"] == existing_element["key"] for existing_element in elements)


@python_2_unicode_compatible
class DataBuilder(RecordBuilder):
    """Data record builder."""

    _collections = ["Data"]

    def __init__(self, source=None, record=None):
        super(DataBuilder, self).__init__(record, source)

    def __str__(self):
        """Print the current record."""
        return text_type(self.record)

    def validate_record(self):
        """Validate the record in according to the data schema."""
        validate(self.record, "data")

    @filter_empty_parameters
    def add_collection(self, collection):
        """Add collection.

        :param collection: defines the type of the current document
        :type collection: string
        """
        self._append_to("_collections", collection)

    @filter_empty_parameters
    def add_abstract(self, abstract, source=None):
        """Add abstract.

        :param abstract: abstract for the current document.
        :type abstract: string

        :param source: source for the given abstract.
        :type source: string
        """
        self._append_to(
            "abstracts",
            self._sourced_dict(
                source,
                value=abstract.strip(),
            ),
        )

    @filter_empty_parameters
    def add_creation_date(self, date=None):
        """
        Args:
            date (str)
        """
        if date is not None:
            self.record["creation_date"] = normalize_date(date)

    @filter_empty_parameters
    def add_accelerator_experiments_legacy_name(self, legacy_name):
        """Add legacy name in accelerator experiment.

        :type legacy_name: string
        """
        self._append_to("accelerator_experiments", {"legacy_name": legacy_name})

    @filter_empty_parameters
    def add_accelerator_experiment(self, legacy_name, record=None):
        """Add legacy name in accelerator experiment.

        :type legacy_name: string

        :param record: reference to the experiment record
        :type record: dict
        """
        experiment = {"legacy_name": legacy_name}

        if record is not None:
            experiment["record"] = record

        self._append_to("accelerator_experiments", experiment)

    @filter_empty_parameters
    def add_acquisition_source(
        self,
        method,
        date=None,
        submission_number=None,
        internal_uid=None,
        email=None,
        orcid=None,
        source=None,
        datetime=None,
    ):
        """Add acquisition source.

        :type submission_number: integer

        :type email: integer

        :type source: string

        :param date: UTC date in isoformat

                     .. deprecated:: 30.1.0
                        Use ``datetime`` instead.
        :type date: string

        :param method: method of acquisition for the suggested document
        :type method: string

        :param orcid: orcid of the user that is creating the record
        :type orcid: string

        :param internal_uid: id of the user that is creating the record
        :type internal_uid: string

        :param datetime: UTC datetime in ISO 8601 format
        :type datetime: string
        """
        if date is not None:
            if datetime is not None:
                raise ValueError("Conflicting args: 'date' and 'datetime'")
            warnings.warn("Use 'datetime', not 'date'", DeprecationWarning, stacklevel=1)
            datetime = date

        acquisition_source = self._sourced_dict(source)

        if submission_number is not None:
            acquisition_source["submission_number"] = str(submission_number)
        if datetime is not None:
            acquisition_source["datetime"] = datetime
        if email is not None:
            acquisition_source["email"] = email
        if method is not None:
            acquisition_source["method"] = method
        if orcid is not None:
            acquisition_source["orcid"] = orcid
        if internal_uid is not None:
            acquisition_source["internal_uid"] = internal_uid

        self.record["acquisition_source"] = acquisition_source

    @filter_empty_parameters
    def add_author(self, author):
        """Add author.

        :param author: author dict for a given document
        :type author: dict
        """
        self._append_to("authors", author)

    @filter_empty_parameters
    def add_collaboration(self, collaboration):
        """Add collaboration.

        :param collaboration: collaboration for the current document
        :type collaboration: string
        """
        self._append_to("collaborations", {"value": collaboration})

    @filter_empty_parameters
    def add_doi(self, doi, source=None, material=None):
        """Add doi.

        :param doi: doi for the current document.
        :type doi: string

        :param source: source for the doi.
        :type source: string

        :param material: material for the doi.
        :type material: string
        """
        if doi is None:
            return

        try:
            doi = normalize_doi(doi)
        except AttributeError:
            return

        if not doi:
            return

        dois = self._sourced_dict(source, value=doi)
        if material is not None:
            dois["material"] = material

        self._append_to("dois", dois)

    @filter_empty_parameters
    def add_keyword(self, keyword, source=None):
        """Add a keyword.

        Args:
            keyword(str): keyword to add.
            source(str): source for the keyword.
        """
        keyword_dict = self._sourced_dict(source, value=keyword)

        self._append_to("keywords", keyword_dict)

    @filter_empty_parameters
    def add_title(self, title, subtitle=None, source=None):
        """Add title.

        :param title: title for the current document
        :type title: string

        :param subtitle: subtitle for the current document
        :type subtitle: string

        :param source: source for the given title
        :type source: string
        """
        title_entry = self._sourced_dict(
            source,
            title=title,
        )

        if subtitle is not None:
            title_entry["subtitle"] = subtitle

        self._append_to("titles", title_entry)

    @staticmethod
    def _prepare_url(value, description=None):
        """Build url dict satisfying url.yml requirements

        Args:
            value (str): URL itself
            description (str): URL description
        """
        entry = {"value": value}
        if description:
            entry["description"] = description
        return entry

    @filter_empty_parameters
    def add_url(self, value, description=None):
        """Add url dict to ``urls`` list.

        Args:
            value (str): Url itself.
            description (str): Description of the url.
        """
        entry = self._prepare_url(value, description)
        self._append_to("urls", entry)

    @filter_empty_parameters
    def add_literature(self, doi=None, record=None, source=None):
        """Add literature.

        :param doi: doi of the literature
        :type doi: str

        :param record: dictionary with ``$ref`` pointing to proper record.
        :type record: dict

        :param source: source of the doi
        :type source: str
        """
        literature_dict = {
            "record": record,
        }

        if doi:
            if source:
                literature_dict["doi"] = self._sourced_dict(source, value=doi)
            else:
                literature_dict["doi"] = {"value": doi}

        self._append_to("literature", literature_dict)
