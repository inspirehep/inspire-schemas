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

from itertools import chain

from inspire_utils.record import get_value


class LiteratureReader(object):
    """Literature record reader."""

    def __init__(self, record):
        self.record = record

    @property
    def abstract(self):
        """Return the first abstract of a record.

        Returns:
            str: the first abstract of the record.

        Examples:
            >>> record = {
            ...     'abstracts': [
            ...         {
            ...             'source': 'arXiv',
            ...             'value': 'Probably not.',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).abstract()
            'Probably not.'

        """
        return get_value(self.record, 'abstracts.value[0]', default='')

    @property
    def arxiv_categories(self):
        """Return all the arXiv categories of a record.

        Returns:
            list(str): all the arXiv categories of the record.

        Examples:
            >>> record = {
            ...     'arxiv_eprints': [
            ...         {
            ...             'categories': [
            ...                 'hep-th',
            ...                 'hep-ph',
            ...             ],
            ...             'value': '1612.08928',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).arxiv_categories()
            ['hep-th', 'hep-ph']

        """
        return list(chain.from_iterable(
            get_value(self.record, 'arxiv_eprints.categories', default=[])))

    @property
    def arxiv_id(self):
        """Return the first arXiv identifier of a record.

        Returns:
            str: the first arXiv identifier of the record.

        Examples:
            >>> record = {
            ...     'arxiv_eprints': [
            ...         {
            ...             'categories': [
            ...                 'hep-th',
            ...                 'hep-ph',
            ...             ],
            ...             'value': '1612.08928',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).arxiv_id()
            '1612.08928'

        """
        return get_value(self.record, 'arxiv_eprints.value[0]', default='')

    @property
    def collaborations(self):
        """Return the collaborations associated with a record.

        Returns:
            list(str): the collaborations associated with the record.

        Examples:
            >>> record = {'collaborations': [{'value': 'CMS'}]}
            >>> LiteratureReader(record).collaborations()
            ['CMS']

        """
        return get_value(self.record, 'collaborations.value', default=[])

    @property
    def inspire_categories(self):
        """Return all the INSPIRE categories of a record.

        Returns:
            list(str): all the INSPIRE categories of the record.

        Examples:
            >>> record = {
            ...     'inspire_categories': [
            ...         {'term': 'Experiment-HEP'},
            ...     ],
            ... }
            >>> LiteratureReader(record).inspire_categories()
            ['Experiment-HEP']

        """
        return get_value(self.record, 'inspire_categories.term', default=[])

    @property
    def keywords(self):
        """Return the keywords assigned to a record.

        Args:
            record(InspireRecord): a record.

        Returns:
            list(str): the keywords assigned to the record.

        Examples:
            >>> record = {
            ...     'keywords': [
            ...         {
            ...             'schema': 'INSPIRE',
            ...             'value': 'CKM matrix',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).keywords()
            ['CKM matrix']

        """
        return get_value(self.record, 'keywords.value', default=[])

    @property
    def method(self):
        """Return the acquisition method of a record.

        Returns:
            str: the acquisition method of the record.

        Examples:
            >>> record = {
            ...     'acquisition_source': {
            ...         'method': 'oai',
            ...         'source': 'arxiv',
            ...     }
            ... }
            >>> LiteratureReader(record).method()
            'oai'

        """
        return get_value(self.record, 'acquisition_source.method', default='')

    @property
    def source(self):
        """Return the acquisition source of a record.

        Returns:
            str: the acquisition source of the record.

        Examples:
            >>> record = {
            ...     'acquisition_source': {
            ...         'method': 'oai',
            ...         'source': 'arxiv',
            ...     }
            ... }
            >>> LiteratureReader(record).source()
            'arxiv'

        """
        return get_value(self.record, 'acquisition_source.source', default='')

    @property
    def subtitle(self):
        """Return the first subtitle of a record.

        Returns:
            str: the first subtitle of the record.

        Examples:
            >>> record = {
            ...     'titles': [
            ...         {
            ...             'subtitle': 'A mathematical exposition',
            ...             'title': 'The General Theory of Relativity',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).subtitle()
            'A mathematical exposition'

        """
        return get_value(self.record, 'titles.subtitle[0]', default='')

    @property
    def title(self):
        """Return the first title of a record.

        Returns:
            str: the first title of the record.

        Examples:
            >>> record = {
            ...     'titles': [
            ...         {
            ...             'subtitle': 'A mathematical exposition',
            ...             'title': 'The General Theory of Relativity',
            ...         },
            ...     ],
            ... }
            >>> LiteratureReader(record).title()
            'The General Theory of Relativity'

        """
        return get_value(self.record, 'titles.title[0]', default='')
