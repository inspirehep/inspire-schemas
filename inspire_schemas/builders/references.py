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

"""Reference builder class and related code."""

from __future__ import absolute_import, division, print_function

import re

import six
from inspire_utils.date import normalize_date
from inspire_utils.name import normalize_name
from isbn import ISBN

import idutils

from ..utils import convert_old_publication_info_to_new, split_pubnote


# Matches any separators for author enumerations.
RE_SPLIT_AUTH = re.compile(r',?\s+and\s|,?\s*&|,|et al\.?|\(?eds?\.\)?',
                           re.I | re.U)
# Matches any stream of initials (A. B C D. -E F).
RE_INITIALS_ONLY = re.compile(r'^\s*-?[A-Z]((\.|\s)\s*-?[A-Z])*\.?\s*$',
                              re.U)
# Matches new style arXiv ID, with an old-style class specification
# (Malformed, but appears in APS records)
RE_ARXIV_POST_2007_CLASS = re.compile(
    "(arxiv:)?(?:[a-z\-]+)(?:\.[a-z]{2})?/(\d{4})\.(\d{4,5})(v\d+)?$",
    flags=re.I
)


def _split_refextract_authors_str(authors_str):
    """Extract author names out of refextract authors output."""
    author_seq = (x.strip() for x in RE_SPLIT_AUTH.split(authors_str) if x)
    res = []

    current = ''
    for author in author_seq:
        if not isinstance(author, six.text_type):
            author = six.text_type(author.decode('utf8', 'ignore'))

        # First clean the token.
        author = re.sub(r'\(|\)', '', author, re.U)
        # Names usually start with characters.
        author = re.sub(r'^[\W\d]+', '', author, re.U)
        # Names should end with characters or dot.
        author = re.sub(r'[^.\w]+$', '', author, re.U)

        # If we have initials join them with the previous token.
        if RE_INITIALS_ONLY.match(author):
            current += ', ' + author.strip().replace('. ', '.')
        else:
            if current:
                res.append(current)
            current = author

    # Add last element.
    if current:
        res.append(current)

    # Manual filterings that we don't want to add in regular expressions since
    # it would make them more complex.
    #  * ed might sneak in
    #  * many legacy refs look like 'X. and Somebody E.'
    #  * might miss lowercase initials
    filters = [
        lambda a: a == 'ed',
        lambda a: a.startswith(','),
        lambda a: len(a) == 1
    ]
    res = [r for r in res if all(not f(r) for f in filters)]
    return res


def _is_arxiv(obj):
    """Return ``True`` if ``obj`` contains an arXiv identifier.

    The ``idutils`` library only handles arXiv identifiers, e.g. strings
    of the form ``arXiv:yymm.xxxxx``, but we sometimes have to deal with
    arXiv references, which might contain more information separated by
    a space. Therefore this helper wraps ``idutils`` to support this case.
    """
    arxiv_test = obj.split()
    if not arxiv_test:
        return False
    return idutils.is_arxiv(arxiv_test[0]) \
        or RE_ARXIV_POST_2007_CLASS.match(arxiv_test[0])


def _normalize_arxiv(obj):
    """Return a normalized arXiv identfier.

    As in ``_is_arxiv``, we need to handle arXiv references as well
    as arXiv identifiers. We also need to return a simpler arXiv
    identifier than what ``idutils`` would output, so we use some
    of its helpers instead of ``normalize_arxiv``.
    """
    obj = obj.split()[0]

    m = idutils.is_arxiv_pre_2007(obj)
    if m:
        return ''.join(m.group(2, 4, 5))

    m = idutils.is_arxiv_post_2007(obj) or RE_ARXIV_POST_2007_CLASS.match(obj)
    if m:
        return '.'.join(m.group(2, 3))


class ReferenceBuilder(object):
    """Class used for building JSON reference objects given simple properties.

    Use this when:
        * Converting from MARC to Literature
        * Parsing refextract output
        * Pushing a record from Holdingpen

    We wrote this in a non-pythonic non-generic way so it's extensible to any
    format a reference field might take.
    """

    RE_VALID_CNUM = re.compile(r'C\d{2}-\d{2}-\d{2}(\.\d+)?')
    RE_VALID_PUBNOTE = re.compile(r'.+,.+,.+(,.*)?')

    def __init__(self):
        self.obj = {}

    def _ensure_field(self, field_name, value):
        if field_name not in self.obj:
            self.obj[field_name] = value

    def _ensure_reference_field(self, field_name, value):
        if 'reference' not in self.obj:
            self.obj['reference'] = {}
        if field_name not in self.obj['reference']:
            self.obj['reference'][field_name] = value

    def _set_publication_info_field(self, field_name, value):
        """Put a value in the publication info of the reference."""
        self._ensure_reference_field('publication_info', {})
        self.obj['reference']['publication_info'][field_name] = value

    def set_label(self, label):
        self._ensure_reference_field('label', label)

    def set_record(self, record):
        self.obj['record'] = record
        self._ensure_field('curated_relation', False)

    def curate(self):
        self.obj['curated_relation'] = True

    def set_texkey(self, texkey):
        self._ensure_reference_field('texkey', texkey)

    def add_title(self, title):
        self._ensure_reference_field('title', {})
        self.obj['reference']['title'] = {'title': title}

    def add_parent_title(self, title):
        self._ensure_reference_field('publication_info', {})
        self.obj['reference']['publication_info']['parent_title'] = title

    def add_misc(self, misc):
        self._ensure_reference_field('misc', [])
        self.obj['reference']['misc'].append(misc)

    def add_raw_reference(self, raw_reference, source=None, ref_format='text'):
        raw_ref = {
            'schema': ref_format,
            'value': raw_reference,
        }
        if source:
            raw_ref['source'] = source

        self._ensure_field('raw_refs', [])
        self.obj['raw_refs'].append(raw_ref)

    def set_year(self, year):
        try:
            year = int(year)
        except (ValueError, TypeError):
            return
        if year >= 1000 and year <= 2050:
            self._ensure_reference_field('publication_info', {})
            self.obj['reference']['publication_info']['year'] = year

    def add_url(self, url):
        self._ensure_reference_field('urls', [])
        self.obj['reference']['urls'].append({'value': url})

    def add_refextract_authors_str(self, authors_str):
        """Parses individual authors from refextracted authors string."""
        for author in _split_refextract_authors_str(authors_str):
            self.add_author(author)

    def add_author(self, full_name, role=None):
        self._ensure_reference_field('authors', [])

        if role is not None:
            inspire_role = 'editor' if role == 'ed.' else role
            self.obj['reference']['authors'].append({
                'full_name': normalize_name(full_name),
                'inspire_role': inspire_role,
            })
        else:
            self.obj['reference']['authors'].append({
                'full_name': normalize_name(full_name),
            })

    def set_pubnote(self, pubnote):
        """Parse pubnote and populate correct fields."""
        if 'publication_info' in self.obj.get('reference', {}):
            self.add_misc(u'Additional pubnote: {}'.format(pubnote))
            return

        if self.RE_VALID_PUBNOTE.match(pubnote):
            pubnote = split_pubnote(pubnote)
            pubnote = convert_old_publication_info_to_new([pubnote])[0]
            self._ensure_reference_field('publication_info', pubnote)
        else:
            self.add_misc(pubnote)

    def set_publisher(self, publisher):
        self._ensure_reference_field('imprint', {})
        self.obj['reference']['imprint']['publisher'] = publisher

    def set_imprint_date(self, date):
        self._ensure_reference_field('imprint', {})
        self.obj['reference']['imprint']['date'] = normalize_date(date)

    def set_imprint_place(self, place):
        self._ensure_reference_field('imprint', {})
        self.obj['reference']['imprint']['place'] = place

    def add_report_number(self, repno):
        # For some reason we get more recall by trying the first part in
        # splitting the report number.
        repno = repno or ''
        if _is_arxiv(repno):
            self._ensure_reference_field('arxiv_eprint',
                                         _normalize_arxiv(repno))
        else:
            self._ensure_reference_field('report_numbers', [])
            self.obj['reference']['report_numbers'].append(repno)

    def add_uid(self, uid):
        """Add unique identifier in correct field."""
        # We might add None values from wherever. Kill them here.
        uid = uid or ''
        if _is_arxiv(uid):
            self._ensure_reference_field('arxiv_eprint', _normalize_arxiv(uid))
        elif idutils.is_doi(uid):
            self._ensure_reference_field('dois', [])
            self.obj['reference']['dois'].append(idutils.normalize_doi(uid))
        elif idutils.is_handle(uid):
            self._ensure_reference_field('persistent_identifiers', [])
            self.obj['reference']['persistent_identifiers'].append({
                'schema': 'HDL',
                'value': idutils.normalize_handle(uid),
            })
        elif idutils.is_urn(uid):
            self._ensure_reference_field('persistent_identifiers', [])
            self.obj['reference']['persistent_identifiers'].append({
                'schema': 'URN',
                'value': uid,
            })
        elif self.RE_VALID_CNUM.match(uid):
            self._ensure_reference_field('publication_info', {})
            self.obj['reference']['publication_info']['cnum'] = uid
        else:
            # ``idutils.is_isbn`` is too strict in what it accepts.
            try:
                isbn = str(ISBN(uid))
                self._ensure_reference_field('isbn', {})
                self.obj['reference']['isbn'] = isbn
            except Exception:
                self.add_misc(uid)

    def add_collaboration(self, collaboration):
        self._ensure_reference_field('collaborations', [])
        self.obj['reference']['collaborations'].append(collaboration)

    def set_journal_title(self, journal_title):
        """Add journal title."""
        self._set_publication_info_field('journal_title', journal_title)

    def set_journal_issue(self, journal_issue):
        """Add journal issue."""
        self._set_publication_info_field('journal_issue', journal_issue)

    def set_journal_volume(self, journal_volume):
        """Add journal volume."""
        self._set_publication_info_field('journal_volume', journal_volume)

    def set_page_artid(self, page_start=None, page_end=None, artid=None):
        """Add artid, start, end pages to publication info of a reference.

        Args:
            page_start(Optional[string]): value for the field page_start
            page_end(Optional[string]): value for the field page_end
            artid(Optional[string]): value for the field artid

        Raises:
            ValueError: when no start_page given for an end_page
        """
        if page_end and not page_start:
            raise ValueError('End_page provided without start_page')

        self._ensure_reference_field('publication_info', {})
        publication_info = self.obj['reference']['publication_info']
        if page_start:
            publication_info['page_start'] = page_start
        if page_end:
            publication_info['page_end'] = page_end
        if artid:
            publication_info['artid'] = artid
