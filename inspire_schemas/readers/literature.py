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
from six import text_type

from inspire_schemas.builders.literature import is_citeable
from inspire_utils.helpers import force_list
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
            >>> LiteratureReader(record).abstract
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
            >>> LiteratureReader(record).arxiv_categories
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
            >>> LiteratureReader(record).arxiv_id
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
            >>> LiteratureReader(record).collaborations
            ['CMS']

        """
        return get_value(self.record, 'collaborations.value', default=[])

    @property
    def document_types(self):
        """Return all document types of a record.

        Returns:
            list(str): all document types of the record.

        Examples:
            >>> LiteratureReader({'document_type': ['article']}).document_types
            ['article']

        """
        return get_value(self.record, 'document_type', default=[])

    @property
    def doi(self):
        """Return the first DOI of a record.

        Args:
            record(InspireRecord): a record.

        Returns:
            string: the first DOI of the record.

        Examples:
            >>> LiteratureReader({'dois': [{'value': '10.1016/0029-5582(61)90469-2'}]}).doi
            '10.1016/0029-5582(61)90469-2'

        """
        return get_value(self.record, 'dois.value[0]', default='')

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
            >>> LiteratureReader(record).inspire_categories
            ['Experiment-HEP']

        """
        return get_value(self.record, 'inspire_categories.term', default=[])

    @property
    def inspire_id(self):
        """Return the INSPIRE id of a record.

        Returns:
            int: the INSPIRE id of the record.

        Examples:
            >>> LiteratureReader({'control_number': 1507156}).inspire_id
            1507156

        """
        return self.record['control_number']

    @property
    def journal_title(self):
        """Return the title of the journal a record was published into.

        Returns:
            string: the title of the journal the record was published into.

        Examples:
            >>> record = {
            ...     'publication_info': [
            ...         {'journal_title': 'Phys.Part.Nucl.Lett.'},
            ...     ],
            ... }
            >>> LiteratureReader(record).journal_title
            'Phys.Part.Nucl.Lett.'

        """
        return get_value(
            self.record, 'publication_info.journal_title[0]',
            default=''
        )

    @property
    def journal_issue(self):
        """Return the issue of the journal a record was published into.

        Returns:
            string: the issue of the journal the record was published into.

        Examples:
            >>> record = {
            ...    'publication_info': [
            ...        {'journal_issue': '5'},
            ...    ],
            ... }
            >>> LiteratureReader(record).journal_issue
            '5'

        """
        return get_value(
            self.record,
            'publication_info.journal_issue[0]',
            default=''
        )

    @property
    def journal_volume(self):
        """Return the volume of the journal a record was published into.

        Returns:
            string: the volume of the journal the record was published into.

        Examples:
            >>> record = {
            ...     'publication_info': [
            ...         {'journal_volume': 'D94'},
            ...     ],
            ... }
            >>> LiteratureReader(record).journal_volume
            'D94'

        """
        return get_value(
            self.record,
            'publication_info.journal_volume[0]',
            default=''
        )

    @property
    def language(self):
        """Return the first language of a record.

        If it is not specified in the record we assume that the language
        is English, so we return ``'en'``.

        Returns:
            string: the first language of the record.

        Examples:
            >>> LiteratureReader({'languages': ['it']}).language
            'it'

        """
        return get_value(self.record, 'languages[0]', default='en')

    @property
    def keywords(self):
        """Return the keywords assigned to a record.

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
    def peer_reviewed(self):
        """Return True if a record is peer reviewed, False otherwise.

        Returns:
            int: True if the record is peer reviewed, False otherwise.

        Examples:
            >>> LiteratureReader({'refereed': True}).peer_reviewed
            True

        """
        return 'refereed' in self.record and self.record['refereed']

    @property
    def publication_date(self):
        """Return the date in which a record was published.

        Returns:
            string: the date in which the record was published.

        Examples:
            >>> LiteratureReader({'publication_info': [{'year': 2017}]}).publication_date
            '2017'

        """
        return str(get_value(
            self.record,
            'publication_info.year[0]',
            default=''
        ))

    @property
    def is_published(self):
        """Return True if a record is published.

        We say that a record is published if it is citeable, which means that
        it has enough information in a ``publication_info``, or if we know its
        DOI and a ``journal_title``, which means it is in press.

        Returns:
            bool: whether the record is published.

        Examples:
            >>> record = {
            ...     'dois': [
            ...         {'value': '10.1016/0029-5582(61)90469-2'},
            ...     ],
            ...     'publication_info': [
            ...         {'journal_title': 'Nucl.Phys.'},
            ...     ],
            ... }
            >>> LiteratureReader(record).is_published
            True

        """
        citeable = 'publication_info' in self.record and \
            is_citeable(self.record['publication_info'])

        submitted = 'dois' in self.record and any(
            'journal_title' in el for el in
            force_list(self.record.get('publication_info'))
        )

        return citeable or submitted

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
            >>> LiteratureReader(record).source
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
            >>> LiteratureReader(record).subtitle
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
            >>> LiteratureReader(record).title
            'The General Theory of Relativity'

        """
        return get_value(self.record, 'titles.title[0]', default='')

    @staticmethod
    def get_page_artid_for_publication_info(publication_info, separator):
        """Return the page range or the article id of a publication_info entry.

        Args:
            publication_info(dict): a publication_info field entry of a record
            separator(basestring): optional page range symbol, defaults to a single dash

        Returns:
            string: the page range or the article id of the record.

        Examples:
            >>> publication_info = {'artid': '054021'}
            >>> get_page_artid(publication_info)
            '054021'

        """
        if 'artid' in publication_info:
            return publication_info['artid']

        elif 'page_start' in publication_info and 'page_end' in publication_info:
            page_start = publication_info['page_start']
            page_end = publication_info['page_end']
            return text_type('{}{}{}').format(
                page_start, text_type(separator), page_end
            )

        return ''

    def get_page_artid(self, separator='-'):
        """Return the page range or the article id of a record.

        Args:
            separator(basestring): optional page range symbol, defaults to a single dash

        Returns:
            string: the page range or the article id of the record.

        Examples:
            >>> record = {
            ...     'publication_info': [
            ...         {'artid': '054021'},
            ...     ],
            ... }
            >>> LiteratureReader(record).get_page_artid()
            '054021'

        """
        publication_info = get_value(
            self.record,
            'publication_info[0]',
            default={}
        )
        return LiteratureReader.get_page_artid_for_publication_info(
            publication_info,
            separator
        )
