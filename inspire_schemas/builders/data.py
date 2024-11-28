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

import contextlib
import warnings

import idutils
from inspire_utils.date import normalize_date
from six import python_2_unicode_compatible, string_types, text_type

from inspire_schemas.builders.builder import RecordBuilder
from inspire_schemas.builders.signatures import SignatureBuilder
from inspire_schemas.utils import (
    filter_empty_parameters,
    get_license_from_url,
    normalize_collaboration,
    normalize_isbn,
    validate,
)


def is_citeable(publication_info):
    """Check some fields in order to define if the article is citeable.

    :param publication_info: publication_info field
    already populated
    :type publication_info: list
    """

    def _item_has_pub_info(item):
        return all(key in item for key in ('journal_title', 'journal_volume'))

    def _item_has_page_or_artid(item):
        return any(key in item for key in ('page_start', 'artid'))

    has_pub_info = any(_item_has_pub_info(item) for item in publication_info)
    has_page_or_artid = any(_item_has_page_or_artid(item) for item in publication_info)

    return has_pub_info and has_page_or_artid


def key_already_there(element, elements):
    """Checks if the given element existng by using the key `key`."""
    return any(element['key'] == existing_element['key'] for existing_element in elements)




@python_2_unicode_compatible
class DataBuilder(RecordBuilder):
    """Data record builder."""

    _collections = ['Data']

    def __init__(self, source=None, record=None):
        super(DataBuilder, self).__init__(record, source)

    def __str__(self):
        """Print the current record."""
        return text_type(self.record)

    def validate_record(self):
        """Validate the record in according to the data schema."""
        validate(self.record, 'data')

    
    @filter_empty_parameters
    def add_collection(self, collection):
        """Add collection.

        :param collection: defines the type of the current document
        :type collection: string
        """
        self._append_to('_collections', collection)

    @filter_empty_parameters
    def add_abstract(self, abstract, source=None):
        """Add abstract.

        :param abstract: abstract for the current document.
        :type abstract: string

        :param source: source for the given abstract.
        :type source: string
        """
        self._append_to(
            'abstracts',
            self._sourced_dict(
                source,
                value=abstract.strip(),
            ),
        )

    @filter_empty_parameters
    def add_accelerator_experiments_legacy_name(self, legacy_name):
        """Add legacy name in accelerator experiment.

        :type legacy_name: string
        """
        self._append_to('accelerator_experiments', {'legacy_name': legacy_name})

    @filter_empty_parameters
    def add_accelerator_experiment(self, legacy_name, record=None):
        """Add legacy name in accelerator experiment.

        :type legacy_name: string

        :param record: reference to the experiment record
        :type record: dict
        """
        experiment = {'legacy_name': legacy_name}

        if record is not None:
            experiment['record'] = record

        self._append_to('accelerator_experiments', experiment)

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
            warnings.warn(
                "Use 'datetime', not 'date'", DeprecationWarning, stacklevel=1
            )
            datetime = date

        acquisition_source = self._sourced_dict(source)

        acquisition_source['submission_number'] = str(submission_number)
        for key in ('datetime', 'email', 'method', 'orcid', 'internal_uid'):
            if locals()[key] is not None:
                acquisition_source[key] = locals()[key]

        self.record['acquisition_source'] = acquisition_source

    @filter_empty_parameters
    def add_author(self, author):
        """Add author.

        :param author: author for a given document
        :type author: object that make_author method
        produces
        """
        self._append_to('authors', author)

    @filter_empty_parameters
    def make_author(
        self,
        full_name,
        affiliations=(),
        roles=(),
        raw_affiliations=(),
        source=None,
        ids=(),
        emails=(),
        alternative_names=(),
        record=None,
        affiliations_identifiers=(),
    ):
        """Make a subrecord representing an author.

        Args:
            full_name(str): full name of the author. If not yet in standard
                Inspire form, it will be normalized.
            affiliations(List[str]): Inspire normalized affiliations of the
                author.
            roles(List[str]): Inspire roles of the author.
            raw_affiliations(List[str]): raw affiliation strings of the author.
            source(str): source for the affiliations when
                ``affiliations_normalized`` is ``False``.
            ids(List[Tuple[str,str]]): list of ids of the author, whose
                elements are of the form ``(schema, value)``.
            emails(List[str]): email addresses of the author.
            alternative_names(List[str]): alternative names of the author.
            record(dict): reference to the author record
        Returns:
            dict: a schema-compliant subrecord.
        """
        builder = SignatureBuilder()
        builder.set_full_name(full_name)
        builder.set_record(record)

        for affiliation in affiliations:
            builder.add_affiliation(affiliation)

        for role in roles:
            builder.add_inspire_role(role)

        for raw_affiliation in raw_affiliations:
            builder.add_raw_affiliation(raw_affiliation, source or self.source)

        for id_schema, id_value in ids:
            if id_schema and id_value:
                builder.set_uid(id_value, schema=id_schema)

        for email in emails:
            builder.add_email(email)

        for schema, value in affiliations_identifiers:
            builder.add_affiliations_identifiers(value, schema=schema)

        for alternative_name in alternative_names:
            builder.add_alternative_name(alternative_name)

        return builder.obj

    @filter_empty_parameters
    def add_collaboration(self, collaboration):
        """Add collaboration.

        :param collaboration: collaboration for the current document
        :type collaboration: string
        """
        collaborations = normalize_collaboration(collaboration)
        for collaboration in collaborations:
            self._append_to('collaborations', {'value': collaboration})

    @filter_empty_parameters
    def add_doi(self, doi, source=None):
        """Add doi.

        :param doi: doi for the current document.
        :type doi: string

        :param source: source for the doi.
        :type source: string
        """
        if doi is None:
            return

        try:
            doi = idutils.normalize_doi(doi)
        except AttributeError:
            return

        if not doi:
            return

        dois = self._sourced_dict(source, value=doi)

        self._append_to('dois', dois)
        
    @filter_empty_parameters
    def add_keyword(self, keyword, source=None):
        """Add a keyword.

        Args:
            keyword(str): keyword to add.
            source(str): source for the keyword.
        """
        keyword_dict = self._sourced_dict(source, value=keyword)

        self._append_to('keywords', keyword_dict)

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
            title_entry['subtitle'] = subtitle

        self._append_to('titles', title_entry)

    @filter_empty_parameters
    def add_url(self, url):
        """Add url.

        :param url: url for additional information for the current document
        :type url: string
        """
        self._append_to('urls', {'value': url})

    @filter_empty_parameters
    def add_literature(self, doi, curated_relation=None , record=None):
        """Add literature.
        
        :param doi: doi of the literature
        :type doi: string
        
        :param curated_relation: mark if relation is curated [NOT REQUIRED]
        :type curated_relation: boolean
        
        :param record: dictionary with ``$ref`` pointing to proper record.
        :type record: dict
        """
        
        literature_dict = {
            'doi': doi,
            'curated_relation': curated_relation,
            'record': record,
        }
        
        self._append_to('literature', literature_dict)
