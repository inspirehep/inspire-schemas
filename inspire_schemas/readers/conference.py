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

from inspire_utils.record import get_value


class ConferenceReader(object):
    """Conference record reader."""

    def __init__(self, record):
        self.record = record

    @property
    def city(self):
        """Return the first city of a Conference record.

        Returns:
            string: the first city of the Conference record.

        Examples:
            >>> record = {'addresses': [{'cities': ['Tokyo']}]}
            >>> ConferenceReader(record).city
            'Tokyo'

        """
        return get_value(self.record, 'addresses.cities[0][0]', default='')

    @property
    def country(self):
        """Return the first country of a Conference record.

        Returns:
            string: the first country of the Conference record.

        Examples:
            >>> record = {'address': [{'country_code': 'JP'}]}
            >>> ConferenceReader(record).country
            'jp'

        """
        return get_value(
            self.record,
            'addresses.country_code[0]',
            default=''
        ).lower()

    @property
    def end_date(self):
        """Return the closing date of a conference record.

        Returns:
            string: the closing date of the Conference record.

        Examples:
            >>> record = {'closing_date': '1999-11-19'}
            >>> ConferenceReader(record).end_date
            '1999-11-19'

        """
        return self.record.get('closing_date', '')

    @property
    def start_date(self):
        """Return the opening date of a conference record.

        Returns:
            string: the opening date of the Conference record.

        Examples:
            >>> record = {'opening_date': '1999-11-16'}
            >>> ConferenceReader(record).start_date
            '1999-11-16'

        """
        return self.record.get('opening_date', '')
