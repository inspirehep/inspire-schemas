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

"""Jobs builder class and related code."""

from __future__ import absolute_import, division, print_function

import logging

import six
from jsonschema._format import is_email

from inspire_schemas.builders.builder import RecordBuilder
from inspire_schemas.utils import (
    filter_empty_parameters,
    sanitize_html,
    validate,
)
from inspire_utils.date import normalize_date

LOG = logging.getLogger(__name__)


class JobBuilder(RecordBuilder):
    """Job record builder."""

    _collections = ['Jobs']

    def __init__(self, record=None, source=None,):
        super(JobBuilder, self).__init__(record, source)
        if record is None:
            self.record['status'] = 'pending'

    def validate_record(self):
        """Validate the record in according to the hep schema."""
        validate(self.record, 'jobs')

    @filter_empty_parameters
    def add_private_note(self, value=None, source=None):
        """Add private note to ``_private_notes`` list
        Args:
            value (str): Value of the note.
            source (str): Source of the information in this field
        """
        self._append_to('_private_notes', source=source, value=value)

    @filter_empty_parameters
    def add_accelerator_experiment(
        self,
        accelerator=None,
        curated_relation=None,
        experiment=None,
        institution=None,
        legacy_name=None,
        record=None

    ):
        """Add experiment to ``accelerator_experiment`` field.

        Args:
            accelerator (str)
            curated_relation (bool)
            experiment (str)
            institution (str)
            legacy_name (str)
            record (dict): URL to the referenced resource.
            When it's string, a new object will be created for record
        """
        self._append_to(
            'accelerator_experiments',
            accelerator=accelerator,
            curated_relation=curated_relation,
            experiment=experiment,
            institution=institution,
            legacy_name=legacy_name,
            record=record
        )

    @filter_empty_parameters
    def add_acquisition_source(
        self,
        datetime=None,
        email=None,
        internal_uid=None,
        method=None,
        orcid=None,
        source=None,
        submission_number=None,

    ):
        """Add acquisition source.

        Args:
            datetime (str): UTC datetime in ISO 8601 format
            email (str)
            internal_uid (str): id of the user that is creating the record
            method (str): method of acquisition for the suggested document
            orcid (str): orcid of the user that is creating the record
            source (str)
            submission_number (int)
        """
        acquisition_source = self._sourced_dict(source)

        acquisition_source['submission_number'] = str(submission_number)
        for key in ('datetime', 'email', 'method', 'orcid', 'internal_uid'):
            if locals()[key] is not None:
                acquisition_source[key] = locals()[key]

        self.record['acquisition_source'] = acquisition_source

    @filter_empty_parameters
    def add_arxiv_category(self, category):
        """Add arxiv_category to ``arxiv_categories`` field

        Args:
            category (str)
        """
        if category != 'other':
            self._append_to('arxiv_categories', category)

    @filter_empty_parameters
    def add_contact(self, name=None, email=None, curated_relation=None, record=None):
        """Add contact object to list of ``contact_details.``

        Args:
            name (str): Name of the contact.
            email (str): Email to the contact.
            curated_relation (bool): Mark if relation is curated [NOT REQUIRED]
            record (dict): dictionary with ``$ref`` pointing to proper record.
            If string, then will be converted to proper dict
        """
        self._append_to(
            'contact_details',
            name=name,
            email=email,
            curated_relation=curated_relation,
            record=record,
        )

    @filter_empty_parameters
    def add_external_system_identifiers(self, value, schema):
        """Add external job identifier to ``external_system_identifiers`` field.

        Args:
            value (str)
            schema (str)
        """
        self._append_to(
            'external_system_identifiers',
            schema=schema,
            value=value,
        )

    @filter_empty_parameters
    def add_institution(self, value, curated_relation=None, record=None):
        """Add institution to ``institutions`` list.

        Args:
            value (str)
            curated_relation (bool)
            record (dict): Referenced record dict.
            If string, then will be converted to proper dict
        """
        self._append_to(
            'institutions',
            value=value,
            curated_relation=curated_relation,
            record=record
        )

    @filter_empty_parameters
    def add_rank(self, rank):
        """Add rank to ``ranks`` list.
        Args:
            rank (str): Rank which will be added to ``ranks`` list.
            One of the ranks specified in jobs schema.
        """
        self._append_to('ranks', rank)

    @staticmethod
    def _prepare_url(value, description=None):
        """Build url dict satysfying url.yml requirements

        Args:
            value (str): URL itself
            description (str): URL description
        """
        entry = {
            'value': value
        }
        if description:
            entry['description'] = description
        return entry

    @filter_empty_parameters
    def add_reference_email(self, email):
        """Add email to ``reference_letters`` list.

        Args:
            email (str): email itself.
        """
        main_key = 'reference_letters'
        email_key = 'emails'
        self._ensure_dict_field(main_key)
        self._ensure_list_field(email_key, obj=self.record[main_key])
        self.record[main_key][email_key].append(email)

    @filter_empty_parameters
    def add_reference_url(self, value, description=None):
        """Add url to ``reference_letter`` list.

        Args:
            value (str): URL value
            description (str): URL description
        """
        main_key = 'reference_letters'
        url_key = 'urls'
        self._ensure_dict_field(main_key)
        reference_url = self._prepare_url(value, description)
        self._ensure_list_field(url_key, obj=self.record[main_key])
        self.record[main_key][url_key].append(reference_url)

    @filter_empty_parameters
    def add_reference_contacts(self, contacts):
        """Add reference contacts from list of strings where urls and emails
        can be mixed together

        Args:
            contacts (list): List of strings containing emails and urls
        """
        for input in contacts:
            if is_email(input):
                self.add_reference_email(input)
            else:
                self.add_reference_url(input)

    @filter_empty_parameters
    def add_region(self, region):
        """Add region to ``regions`` list.

        Args:
            region (str): Region which will be added to ``regions`` list.
            One of the regions specified in jobs schema.
        """
        self._append_to('regions', region)

    @filter_empty_parameters
    def add_url(self, value, description=None):
        """Add url dict to ``urls`` list.

        Args:
            value (str): Url itself.
            description (str): Description of the url.
        """
        entry = self._prepare_url(value, description)
        self._append_to('urls', entry)

    @filter_empty_parameters
    def set_deadline(self, deadline):
        """Save normalized date of the deadline to ``deadline_date`` field

        deadline (str): Date in format recognized by ``normalize_date``
        """
        self.record['deadline_date'] = normalize_date(deadline)

    @filter_empty_parameters
    def set_external_job_identifier(self, identifier):
        """Set external job identifier in ``external_job_identifier`` field
        Args:
            identifier (str)
        """
        self.record['external_job_identifier'] = identifier

    @filter_empty_parameters
    def set_description(self, description):
        """Set description of job

        Args:
            description (str): Job description
        """
        self.record['description'] = sanitize_html(description)

    @filter_empty_parameters
    def set_status(self, status):
        """Set status to the job.

        Args:
            status (str): String with the status of the job.
        """
        self.record['status'] = status

    @filter_empty_parameters
    def set_title(self, title):
        """Set title for the job to ``position`` field

        Args:
            title (str): Job title
        """
        self.record['position'] = title
