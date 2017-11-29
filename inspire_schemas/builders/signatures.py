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

"""Signatures builder class and related code."""

from __future__ import absolute_import, division, print_function

from inspire_utils.name import normalize_name

from ..utils import (
    filter_empty_parameters,
    author_id_normalize_and_schema,
)
from ..errors import UnknownUIDSchema


class SignatureBuilder(object):
    """Build JSON signatures, which are author entries on litarature records.

    Use this when:
        * Converting from MARC to Literature
        * Pushing a record from Holdingpen

    We wrote this in a non-pythonic non-generic way so it's extensible to any
    format a signature field might take.
    """

    def __init__(self, signature=None):
        """Initializes a signature.

        Initializes a signature to be used within a Literature record.

        Args:
            signature (dict): initialize with an existing signature
        """
        if signature is None:
            signature = {}
        self.obj = signature

    def _ensure_field(self, field_name, value):
        if field_name not in self.obj:
            self.obj[field_name] = value

    def _ensure_list_field(self, field_name, value):
        if value:
            self._ensure_field(field_name, [])
            if value not in self.obj[field_name]:
                self.obj[field_name].append(value)

    def add_affiliation(self, value, curated_relation=None, record=None):
        """Add an affiliation.

        Args:
            value (string): affiliation value
            curated_relation (bool): is relation curated
            record (dict): affiliation JSON reference
        """
        if value:
            affiliation = {
                'value': value
            }
            if record:
                affiliation['record'] = record
            if curated_relation is not None:
                affiliation['curated_relation'] = curated_relation
            self._ensure_list_field('affiliations', affiliation)

    @filter_empty_parameters
    def add_alternative_name(self, alternative_name):
        self._ensure_list_field('alternative_names', alternative_name)

    @filter_empty_parameters
    def add_credit_role(self, credit_role):
        self._ensure_list_field('credit_roles', credit_role)

    @filter_empty_parameters
    def add_email(self, email):
        self._ensure_list_field('emails', email)

    @filter_empty_parameters
    def set_full_name(self, full_name):
        self._ensure_field('full_name', normalize_name(full_name))

    @filter_empty_parameters
    def _add_uid(self, uid, schema):
        self._ensure_list_field('ids', {
            'value': uid,
            'schema': schema
        })

    @filter_empty_parameters
    def set_uid(self, uid, schema=None):
        """Set a unique ID.

        If a UID of a given schema already exists in a record it will
        be overwritten, otherwise it will be appended to the record.

        Args:
            uid (string): unique identifier.
            schema (Optional[string]): schema of the unique identifier. If
                ``None``, the schema will be guessed based on the shape of
                ``uid``.

        Raises:
            SchemaUIDConflict: it UID and schema are not matching
        """
        try:
            uid, schema = author_id_normalize_and_schema(uid, schema)
        except UnknownUIDSchema:
            # Explicit schema wasn't provided, and the UID is too little
            # to figure out the schema of it, this however doesn't mean
            # the UID is invalid
            pass

        self._ensure_field('ids', [])
        self.obj['ids'] = [id_ for id_ in self.obj['ids'] if id_.get('schema') != schema]
        self._add_uid(uid, schema)

    @filter_empty_parameters
    def add_inspire_role(self, inspire_role):
        self._ensure_list_field('inspire_roles', inspire_role)

    @filter_empty_parameters
    def add_raw_affiliation(self, raw_affiliation, source=None):
        raw_aff_field = {'value': raw_affiliation}
        if source:
            raw_aff_field['source'] = source
        self._ensure_list_field('raw_affiliations', raw_aff_field)

    @filter_empty_parameters
    def set_record(self, record):
        self.obj['record'] = record

    def curate(self):
        self.obj['curated_relation'] = True
