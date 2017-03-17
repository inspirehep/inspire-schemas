# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2017 CERN.
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

"""Builder classes and related code."""

from __future__ import absolute_import, division, print_function

import warnings
from functools import wraps
import idutils

from .utils import (normalize_author_name_with_comma, normalize_date_iso,
                    validate)


def filter_empty_parameters(func):
    """Decorator that is filtering empty parameters.

    :param func: function that you want wrapping
    :type func: function
    """
    @wraps(func)
    def func_wrapper(self, *args, **kwargs):
        empties = [None, '', [], {}]
        my_kwargs = {key: value for key, value in kwargs.items()
                     if value not in empties}

        if (
            list(my_kwargs.keys()) == ['source'] or not list(my_kwargs.keys())
        ) and args == ():
            return
        return func(self, *args, **my_kwargs)

    return func_wrapper


def is_citeable(publication_info):
    """Check some fields in order to define if the article is citeable.

    :param publication_info: publication_info field
    already populated
    :type publication_info: list
    """
    def _item_has_pub_info(item):
        return all(
            key in item for key in (
                'journal_title', 'journal_volume'
            )
        )

    def _item_has_page_or_artid(item):
        return any(
            key in item for key in (
                'page_start', 'artid'
            )
        )

    has_pub_info = any(
        _item_has_pub_info(item) for item in publication_info
    )
    has_page_or_artid = any(
        _item_has_page_or_artid(item) for item in publication_info
    )

    return has_pub_info and has_page_or_artid


class LiteratureBuilder(object):
    """Literature record builder."""

    def __init__(self, source, record=None):
        """Init method.

        :param source: sets the default value for the 'source' fields
         of the current record, which captures where the information
         that the builder populates comes from
        :type source: string

        :param record: sets the default value for the the current
        record, in order to edit an already existent record
        :type record: dict
        """
        self.record = {} if record is None else record
        self.source = source

    def __str__(self):
        """Print the current record."""
        return str(self.record)

    def __repr__(self):
        """Printable representation of the builder."""
        return 'LiteratureBuilder(source="{}", record={})'.format(
            self.source,
            self.record
        )

    def _get_source(self, source):
        if source is not None:
            return source
        return self.source

    def validate_record(self):
        """Validate the record in according to the hep schema."""
        validate(self.record, 'hep')

    @filter_empty_parameters
    def add_abstract(self, abstract, source=None):
        """Add abstract.

        :param abstract: abstract for the current document.
        :type abstract: string

        :param source: source for the given abstract.
        :type source: string
        """
        self.record.setdefault('abstracts', [])

        self.record['abstracts'].append({
            'value': abstract.strip(),
            'source': self._get_source(source),
        })

    @filter_empty_parameters
    def add_arxiv_eprint(self, arxiv_id, arxiv_categories):
        """Add arxiv eprint.

        :param arxiv_id: arxiv id for the current document.
        :type arxiv_id: string

        :param arxiv_categories: arXiv categories for the current document.
        :type arxiv_categories: list
        """
        self.record.setdefault('arxiv_eprints', [])

        self.record['arxiv_eprints'].append({
            'value': arxiv_id,
            'categories': arxiv_categories,
        })
        self.set_citeable(True)

    @filter_empty_parameters
    def add_doi(self, doi, source=None):
        """Add doi.

        :param doi: doi for the current document.
        :type doi: string

        :param source: source for the doi.
        :type source: string
        """
        self.record.setdefault('dois', [])

        if idutils.normalize_doi(doi):
            self.record['dois'].append({
                'value': doi,
                'source': self._get_source(source),
            })

    @filter_empty_parameters
    def add_author(self, author):
        """Add author.

        :param author: author for a given document
        :type author: object that make_author method
        produces
        """
        self.record.setdefault('authors', [])

        self.record['authors'].append(author)

    @staticmethod
    def make_author(full_name, affiliations=None, roles=None):
        """Make a dictionary that is representing an author.

        :param full_name: author full name
        Format: surname, name
        :type full_name: string

        :param affiliations: author affiliations
        :type affiliations: list

        :param roles: it tells the roles of the current author
        :type roles: list

        :rtype: dict
        """
        def _add_affiliations(author, affiliations):
            author.setdefault('affiliations', [])
            for affiliation in affiliations:
                if affiliation:
                    author['affiliations'].append({
                        'value': affiliation
                    })
            return author

        author = {}

        author['full_name'] = normalize_author_name_with_comma(full_name)

        if affiliations is not None:
            author = _add_affiliations(author, affiliations)

        if isinstance(roles, list):
            author['inspire_roles'] = roles

        return author

    @filter_empty_parameters
    def add_inspire_categories(self, subject_terms, source=None):
        """Add inspire categories.

        :param subject_terms: user categories for the current document.
        :type subject_terms: list

        :param source: source for the given categories.
        :type source: string
        """
        self.record.setdefault('inspire_categories', [])

        self.record['inspire_categories'].extend([{
            'term': category,
            'source': self._get_source(source),
        } for category in subject_terms])

    @filter_empty_parameters
    def add_private_note(self, private_notes, source=None):
        """Add private notes.

        :param private_notes: hidden notes for the current document
        :type private_notes: string

        :param source: source for the given private notes
        :type source: string
        """
        self.record.setdefault('_private_notes', [])

        self.record['_private_notes'].append({
            'value': private_notes,
            'source': self._get_source(source),
        })

    @filter_empty_parameters
    def add_publication_info(
        self,
        year=None,
        cnum=None,
        artid=None,
        page_end=None,
        page_start=None,
        journal_issue=None,
        journal_title=None,
        journal_volume=None
    ):
        """Add publication info.

        :param year: year of publication
        :type year: integer

        :param cnum: inspire conference number
        :type cnum: string

        :param artid: article id
        :type artid: string

        :param page_end: final page for the article
        :type page_end: string

        :param page_start: initial page for the article
        :type page_start: string

        :param journal_issue: issue of the journal where
        the document has been published
        :type journal_issue: string

        :param journal_title: title of the journal where
        the document has been published
        :type journal_title: string

        :param journal_volume: volume of the journal where
        the document has been published
        :type journal_volume: string
        """
        self.record.setdefault('publication_info', [])

        publication_item = {}
        for key in ('cnum', 'artid', 'page_end', 'page_start',
                    'journal_issue', 'journal_title',
                    'journal_volume', 'year'):
            if locals()[key] is not None:
                publication_item[key] = locals()[key]

        if page_start and page_end:
            try:
                self.add_number_of_pages(
                    int(page_end) - int(page_start) + 1
                )
            except (TypeError, ValueError):
                pass

        self.record['publication_info'].append(publication_item)

        if is_citeable(self.record['publication_info']):
            self.set_citeable(True)

    @filter_empty_parameters
    def add_imprint_date(self, imprint_date):
        """Add imprint date.

        :type imprint_date: string. A formatted date is required (yyyy-mm-dd)
        """
        self.record.setdefault('imprints', [])

        self.record['imprints'].append({
            'date': normalize_date_iso(imprint_date)
        })

    @filter_empty_parameters
    def add_preprint_date(self, preprint_date):
        """Add preprint date.

        :type preprint_date: string. A formatted date is required (yyyy-mm-dd)
        """
        self.record['preprint_date'] = normalize_date_iso(preprint_date)

    @filter_empty_parameters
    def add_thesis(
        self,
        defense_date=None,
        degree_type=None,
        institution=None,
        date=None
    ):
        """Add thesis info.

        :param defense_date: defense date for the current thesis
        :type defense_date: string. A formatted date is required (yyyy-mm-dd)

        :param degree_type: degree type for the current thesis
        :type degree_type: string

        :param institution: author's affiliation for the current thesis
        :type institution: string

        :param date: publication date for the current thesis
        :type date: string. A formatted date is required (yyyy-mm-dd)
        """
        self.record.setdefault('thesis_info', {})

        date = normalize_date_iso(date)
        defense_date = normalize_date_iso(defense_date)

        thesis_item = {}
        for key in ('defense_date', 'date'):
            if locals()[key] is not None:
                thesis_item[key] = locals()[key]

        if degree_type is not None:
            thesis_item['degree_type'] = degree_type.lower()

        if institution is not None:
            thesis_item['institutions'] = [{'name': institution}]

        self.record['thesis_info'] = thesis_item

    @filter_empty_parameters
    def add_accelerator_experiments_legacy_name(self, legacy_name):
        """Add legacy name in accelerator experiment.

        :type legacy_name: string
        """
        self.record.setdefault('accelerator_experiments', [])

        self.record['accelerator_experiments'].append({
            'legacy_name': legacy_name
        })

    @filter_empty_parameters
    def add_language(self, language):
        """Add language.

        :param language: language for the current document
        :type language: string (2 characters ISO639-1)
        """
        self.record.setdefault('languages', [])

        self.record['languages'].append(language)

    @filter_empty_parameters
    def add_license(self, url=None, license=None):
        """Add license.

        :param url: url for the description of the license
        :type url: string

        :param license: license type
        :type license: string
        """
        self.record.setdefault('license', [])

        hep_license = {}
        for key in ('url', 'license'):
            if locals()[key] is not None:
                hep_license[key] = locals()[key]

        self.record['license'].append(hep_license)

    @filter_empty_parameters
    def add_public_note(self, public_note, source=None):
        """Add public note.

        :param public_note: public note for the current article.
        :type public_note: string

        :param source: source for the given notes.
        :type source: string
        """
        self.record.setdefault('public_notes', [])

        self.record['public_notes'].append({
            'value': public_note,
            'source': self._get_source(source),
        })

    @filter_empty_parameters
    def add_title(self, title, source=None):
        """Add title.

        :param title: title for the current document
        :type title: string

        :param source: source for the given title
        :type source: string
        """
        self.record.setdefault('titles', [])

        self.record['titles'].append({
            'title': title,
            'source': self._get_source(source),
        })

    @filter_empty_parameters
    def add_title_translation(self, title, language=None, source=None):
        """Add title translation.

        :param title: translated title
        :type title: string

        :param language: language for the original title
        :type language: string (2 characters ISO639-1)

        :param source: source for the given title
        :type source: string
        """
        self.record.setdefault('title_translations', [])

        title_translation = {
            'title': title,
            'source': self._get_source(source),
        }
        if language is not None:
            title_translation['language'] = language

        self.record['title_translations'].append(title_translation)

    @filter_empty_parameters
    def add_url(self, url):
        """Add url.

        :param url: url for additional information for the current document
        :type url: string
        """
        self.record.setdefault('urls', [])

        self.record['urls'].append({
            'value': url
        })

    @filter_empty_parameters
    def add_report_number(self, report_number, source=None):
        """Add report numbers.

        :param report_number: report number for the current document
        :type report_number: string

        :param source: source for the given report number
        :type source: string
        """
        self.record.setdefault('report_numbers', [])

        self.record['report_numbers'].append({
            'value': report_number,
            'source': self._get_source(source),
        })

    @filter_empty_parameters
    def add_collaboration(self, collaboration):
        """Add collaboration.

        :param collaboration: collaboration for the current document
        :type collaboration: string
        """
        self.record.setdefault('collaborations', [])

        self.record['collaborations'].append({
            'value': collaboration
        })

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
            warnings.warn("Use 'datetime', not 'date'", DeprecationWarning)
            datetime = date

        self.record.setdefault('acquisition_source', {})

        acquisition_source = {}

        acquisition_source['submission_number'] = str(submission_number)
        acquisition_source['source'] = self._get_source(source)
        for key in ('datetime', 'email', 'method', 'orcid', 'internal_uid'):
            if locals()[key] is not None:
                acquisition_source[key] = locals()[key]

        self.record['acquisition_source'] = acquisition_source

    @filter_empty_parameters
    def add_document_type(self, document_type):
        """Add document type.

        :type document_type: string
        """
        self.record.setdefault('document_type', [])

        self.record['document_type'].append(document_type)

    @filter_empty_parameters
    def add_copyright(
        self,
        material=None,
        holder=None,
        statement=None,
        url=None
    ):
        """Add Copyright.

        :type material: string

        :type holder: string

        :type statement: string

        :type url: string
        """
        self.record.setdefault('copyright', [])

        copyright = {}
        for key in ('holder', 'statement', 'url'):
            if locals()[key] is not None:
                copyright[key] = locals()[key]

        if material is not None:
            copyright[key] = material.lower()

        self.record['copyright'].append(copyright)

    @filter_empty_parameters
    def add_number_of_pages(self, number_of_pages):
        """Add number_of_pages.

        :type number_of_pages: integer
        """
        self.record['number_of_pages'] = number_of_pages

    @filter_empty_parameters
    def add_special_collection(self, special_collection):
        """Add special_collection.

        :param special_collection: defines the type of the current document
        :type special_collection: string
        """
        self.record.setdefault('special_collections', [])

        self.record['special_collections'].append(special_collection)

    @filter_empty_parameters
    def add_publication_type(self, publication_type):
        """Add publication_type.

        :param publication_type: Defines the type
        of the current document
        :type publication_type: string
        """
        self.record.setdefault('publication_type', [])

        self.record['publication_type'].append(publication_type)

    @filter_empty_parameters
    def set_core(self, core):
        """Set core value.

        :param core: define a core article
        :type core: bool
        """
        self.record['core'] = core

    @filter_empty_parameters
    def set_refereed(self, refereed):
        """Set refereed value.

        :param refereed: define a refereed article
        :type refereed: bool
        """
        self.record['refereed'] = refereed

    @filter_empty_parameters
    def set_withdrawn(self, withdrawn):
        """Set withdrawn value.

        :param withdrawn: define a withdrawn article
        :type withdrawn: bool
        """
        self.record['withdrawn'] = withdrawn

    @filter_empty_parameters
    def set_citeable(self, citeable):
        """Set citeable value.

        :param citeable: define a citeable article
        :type citeable: bool
        """
        self.record['citeable'] = citeable
