# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE.
# Copyright (C) 2014-2017 CERN.
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

"""Author builder class and related code."""

from __future__ import absolute_import, division, print_function

from inspire_schemas.builders.builder import RecordBuilder
from inspire_schemas.utils import filter_empty_parameters, load_schema
from inspire_utils.date import normalize_date, PartialDate
from inspire_utils.helpers import force_list
from inspire_utils.name import normalize_name
from inspire_utils.record import get_value

RANKS = load_schema('elements/rank')['enum']
RANKS.append(None)
INSTITUTION_RANK_TO_PRIORITY = {rank: -idx for (idx, rank) in enumerate(RANKS)}
EARLIEST_DATE = PartialDate.loads('1000')


class AuthorBuilder(RecordBuilder):
    """Author record builder."""

    _collections = ['Authors']

    def __init__(self, author=None, source=None):
        super(AuthorBuilder, self).__init__(author, source)
        self.obj = self.record

    @filter_empty_parameters
    def set_name(self, name):
        """Set the name for the author.

        Args:
            :param name: should be the family name, the given names, or both, and at least one is required.
            :type name: string
        """
        self._ensure_field('name', {})
        self.obj['name']['value'] = normalize_name(name)

    @filter_empty_parameters
    def set_display_name(self, name):
        """Set the preferred name for the author.

        Args:
            :param name: preferred name to be displayed for the author.
            :type name: string
        """
        self._ensure_field('name', {})
        self.obj['name']['preferred_name'] = name

    @filter_empty_parameters
    def add_name_variant(self, name):
        """Add name variant.

        Args:
            :param name: name variant for the current author.
            :type name: string
        """
        self._ensure_field('name', {})
        self.obj['name'].setdefault('name_variants', []).append(name)

    @filter_empty_parameters
    def add_native_name(self, name):
        """Add native name.

        Args:
            :param name: native name for the current author.
            :type name: string
        """
        self._ensure_field('name', {})
        self.obj['name'].setdefault('native_names', []).append(name)

    @filter_empty_parameters
    def add_previous_name(self, name):
        """Add previous name.

        Args:
            :param name: previous name for the current author.
            :type name: string
        """
        self._ensure_field('name', {})
        self.obj['name'].setdefault('previous_names', []).append(name)

    @filter_empty_parameters
    def add_email_address(self, email, hidden=None):
        """Add email address.

        Args:
            :param email: email of the author.
            :type email: string

            :param hidden: if email is public or not.
            :type hidden: boolean
        """
        existing_emails = get_value(self.obj, 'email_addresses', [])
        found_email = next(
            (existing_email for existing_email in existing_emails if existing_email.get('value') == email),
            None
        )
        if found_email is None:
            new_email = {'value': email}
            if hidden is not None:
                new_email['hidden'] = hidden
            self._append_to('email_addresses', new_email)
        elif hidden is not None:
            found_email['hidden'] = hidden

    @filter_empty_parameters
    def set_status(self, status):
        """Set the person's status.

        Args:
            :param status: status from the enumeration of statuses.
            :type status: string
        """
        self.obj['status'] = status

    @filter_empty_parameters
    def add_url(self, url, description=None):
        """Add a personal website.

        Args:
            :param url: url to the person's website.
            :type url: string

            :param description: short description of the website.
            :type description: string
        """
        url = {
            'value': url,
        }
        if description:
            url['description'] = description
        self._append_to('urls', url)

    @filter_empty_parameters
    def add_blog(self, url):
        """Add a personal website as blog.

        Args:
            :param url: url to the person's blog.
            :type url: string
        """
        self.add_url(url, description='blog')

    @filter_empty_parameters
    def add_linkedin(self, id_):
        """Add a linkedIn id.

        Args:
            :param id_: Identifier of LinkedIn profile i.e. the part after ``linkedin.com/in/`` in the URL.
            :type id_: string
        """
        self._append_to('ids', {
            'value': id_,
            'schema': 'LINKEDIN',
        })

    @filter_empty_parameters
    def add_twitter(self, id_):
        """Add a Twitter id.

        Args:
            :param id_: Identifier of Twitter profile i.e. the part after ``twitter.com/`` in the URL.
            :type id_: string
        """
        self._append_to('ids', {
            'value': id_,
            'schema': 'TWITTER',
        })

    @filter_empty_parameters
    def add_orcid(self, id_):
        """Add a ORCID identifier.

        Args:
            :param id_: The ORCID identifier.
            :type id_: string
        """
        self._append_to('ids', {
            'value': id_,
            'schema': 'ORCID',
        })

    @filter_empty_parameters
    def add_bai(self, id_):
        """Add an inspire  BAI identifier.

        Args:
            :param id_: The BAI.
            :type id_: string
        """
        self._append_to('ids', {
            'value': id_,
            'schema': 'INSPIRE BAI',
        })

    @filter_empty_parameters
    def add_arxiv_category(self, category):
        """Add a field of research.

        Args:
            :param category: valid arxiv category related to the field of research.
            :type category: string
        """
        self._append_to('arxiv_categories', category)

    @filter_empty_parameters
    def add_institution(
        self,
        institution,
        start_date=None,
        end_date=None,
        rank=None,
        record=None,
        curated=False,
        current=False,
        hidden=False,
    ):
        """Add an institution where the person works/worked.

        Args:
            :param institution: name of the institution.
            :type institution: string

            :param start_date: the date when the person joined the institution, in any format.
            :type start_date: string

            :param end_date: the date when the person left the institution, in any format.
            :type end_date: string

            :param rank: the rank of academic position of the person inside the institution.
            :type rank: string

            :param record: URI for the institution record.
            :type record: string

            :param curated: if the institution has been curated i.e. has been verified.
            :type curated: boolean

            :param current: if the person is currently associated with this institution.
            :type current: boolean

            :param hidden: if the institution should be visible
            :type hidden: boolean
        """
        new_institution = {}
        new_institution['institution'] = institution
        if start_date:
            new_institution['start_date'] = normalize_date(start_date)
        if end_date:
            new_institution['end_date'] = normalize_date(end_date)
        if rank:
            new_institution['rank'] = rank
        if record:
            new_institution['record'] = record
        new_institution["hidden"] = hidden
        new_institution['curated_relation'] = curated
        new_institution['current'] = current
        self._append_to('positions', new_institution)
        self.obj['positions'].sort(key=self._get_institution_priority_tuple, reverse=True)

    @staticmethod
    def _get_institution_priority_tuple(institution):
        return AuthorBuilder._get_work_priority_tuple(institution) + (
            INSTITUTION_RANK_TO_PRIORITY.get(institution.get('rank')),
        )

    @filter_empty_parameters
    def add_project(
            self, name, record=None, start_date=None, end_date=None, curated=False,
            current=False, hidden=False
    ):
        """Add an experiment that the person worked on.

        Args:
            :param name: name of the experiment.
            :type name: string

            :param start_date: the date when the person started working on the experiment.
            :type start_date: string

            :param end_date: the date when the person stopped working on the experiment.
            :type end_date: string

            :param record: URI for the experiment record.
            :type record: string

            :param curated: if the experiment has been curated i.e. has been verified.
            :type curated: boolean

            :param current: if the person is currently working on this experiment.
            :type current: boolean

            :param hidden: if the project should be visible
            :type hidden: boolean
        """
        new_experiment = {}
        new_experiment['name'] = name
        if start_date:
            new_experiment['start_date'] = normalize_date(start_date)
        if end_date:
            new_experiment['end_date'] = normalize_date(end_date)
        if record:
            new_experiment['record'] = record
        new_experiment["hidden"] = hidden
        new_experiment['curated_relation'] = curated
        new_experiment['current'] = current
        self._append_to('project_membership', new_experiment)
        self.obj['project_membership'].sort(key=self._get_work_priority_tuple, reverse=True)

    @staticmethod
    def _get_work_priority_tuple(work):
        start_date = work.get('start_date')
        return (
            work.get('current'),
            PartialDate.parse(start_date) if start_date else EARLIEST_DATE,
        )

    @filter_empty_parameters
    def add_advisor(self, name, ids=None, degree_type=None, record=None, curated=False, hidden=False):
        """Add an advisor.

        Args:
            :param name: full name of the advisor.
            :type name: string

            :param ids: list with the IDs of the advisor.
            :type ids: list

            :param degree_type: one of the allowed types of degree the advisor helped with.
            :type degree_type: string

            :param record: URI for the advisor.
            :type record: string

            :param curated: if the advisor relation has been curated i.e. has been verified.
            :type curated: boolean

            :param hidden: if advisor should be visible
            :type hidden: boolean
        """
        new_advisor = {}
        new_advisor['name'] = normalize_name(name)
        if ids:
            new_advisor['ids'] = force_list(ids)
        if degree_type:
            new_advisor['degree_type'] = degree_type
        if record:
            new_advisor['record'] = record
        new_advisor["hidden"] = hidden
        new_advisor['curated_relation'] = curated
        self._append_to('advisors', new_advisor)

    @filter_empty_parameters
    def add_private_note(self, note, source=None):
        """Add a private note.

        Args:
            :param comment: comment about the author.
            :type comment: string

            :param source: the source of the comment.
            :type source: string
        """
        note = {
            'value': note,
        }
        if source:
            note['source'] = source
        self._append_to('_private_notes', note)

    @filter_empty_parameters
    def add_acquisition_source(
        self,
        method,
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

        :param method: method of acquisition for the suggested document
        :type method: string

        :param orcid: orcid of the user that is creating the record
        :type orcid: string

        :param internal_uid: id of the user that is creating the record
        :type internal_uid: string

        :param datetime: UTC datetime in ISO 8601 format
        :type datetime: string
        """
        acquisition_source = self._sourced_dict(source)

        acquisition_source['submission_number'] = str(submission_number)
        for key in ('datetime', 'email', 'method', 'orcid', 'internal_uid'):
            if locals()[key] is not None:
                acquisition_source[key] = locals()[key]

        self.obj['acquisition_source'] = acquisition_source
