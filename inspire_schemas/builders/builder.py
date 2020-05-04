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

from __future__ import absolute_import, division, print_function

import six

from ..utils import EMPTIES, filter_empty_parameters


class RecordBuilder(object):
    """Base record builder."""

    _collections = []

    def __init__(self, record=None, source=None):
        if record is None:
            record = {'_collections': [_ for _ in self.__class__._collections]}
        self.record = record
        self.source = source

    def __repr__(self):
        """Printable representation of the builder."""
        return u'{}(source={!r}, record={})'.format(
            type(self).__name__,
            self.source,
            self.record
        )

    @filter_empty_parameters
    def _append_to(self, field, element=None, default_list=None, **kwargs):
        if default_list is None:
            default_list = []
        if element not in EMPTIES:
            self._ensure_list_field(field, default_list)
            if element not in self.record[field]:
                self.record[field].append(element)
        elif kwargs:
            if 'record' in kwargs and isinstance(kwargs['record'], six.string_types):
                kwargs['record'] = {'$ref': kwargs['record']}
            self._ensure_list_field(field, default_list)
            if kwargs not in self.record[field]:
                self.record[field].append(kwargs)

    def _ensure_field(self, field_name, default_value, obj=None):
        if obj is None:
            obj = self.record
        if field_name not in obj:
            obj[field_name] = default_value

    def _ensure_list_field(self, field_name, default_value=None, obj=None):
        if default_value is None:
            default_value = []
        self._ensure_field(field_name, default_value, obj)

    def _ensure_dict_field(self, field_name, default_value=None, obj=None):
        if default_value is None:
            default_value = {}
        self._ensure_field(field_name, default_value, obj)

    def _sourced_dict(self, source=None, **kwargs):
        if source:
            kwargs['source'] = source
        elif self.source:
            kwargs['source'] = self.source

        return {key: value for key, value in kwargs.items() if value not in EMPTIES}
