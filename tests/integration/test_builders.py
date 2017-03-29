# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016 CERN.
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

import yaml
import os

import pytest

from inspire_schemas import api

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_file(file_name):
    path = os.path.join(FIXTURES_PATH, file_name)
    with open(path) as input_data:
        data = yaml.load(input_data.read())

    return data


@pytest.fixture('module')
def expected_data_hep():
    return load_file('expected_data_hep.yaml')


@pytest.fixture('module')
def input_data_hep():
    return load_file('input_data_hep.yaml')


def test_literature_builder_valid_record(input_data_hep, expected_data_hep):

    builder = api.LiteratureBuilder('submitter')

    builder.add_abstract(
        abstract=input_data_hep['abstract'],
    )
    builder.add_arxiv_eprint(
        arxiv_id=input_data_hep['arxiv_id'],
        arxiv_categories=input_data_hep['arxiv_categories']
    )
    builder.add_doi(
        doi=input_data_hep['doi'],
    )
    author = builder.make_author(
        full_name=input_data_hep['full_name'],
        affiliations=input_data_hep['affiliations'],
        roles=input_data_hep['roles']
    )
    builder.add_author(author)

    builder.add_inspire_categories(
        subject_terms=input_data_hep['subject_terms'],
        source=input_data_hep['source_categories']
    )
    builder.add_private_note(
        private_notes=input_data_hep['private_notes']
    )
    builder.add_publication_info(
        year=input_data_hep['year'],
        cnum=input_data_hep['cnum'],
        artid=input_data_hep['artid'],
        page_end=input_data_hep['page_end'],
        page_start=input_data_hep['page_start'],
        journal_issue=input_data_hep['journal_issue'],
        journal_title=input_data_hep['journal_title'],
        journal_volume=input_data_hep['journal_volume']
    )
    builder.add_preprint_date(
        preprint_date=input_data_hep['preprint_date']
    )
    builder.add_thesis(
        defense_date=input_data_hep['defense_date'],
        degree_type=input_data_hep['degree_type'],
        institution=input_data_hep['institution'],
        date=input_data_hep['date']
    )
    builder.add_accelerator_experiments_legacy_name(
        legacy_name=input_data_hep['legacy_name']
    )
    builder.add_language(language=input_data_hep['language'])
    builder.add_license(
        url=input_data_hep['license_url'],
        license=input_data_hep['license']
    )
    builder.add_public_note(
        public_note=input_data_hep['public_note']
    )
    builder.add_title(
        title=input_data_hep['title']
    )
    builder.add_title_translation(
        title=input_data_hep['title'],
        language=input_data_hep['language']
    )
    builder.add_url(url=input_data_hep['url'])
    builder.add_report_number(
        report_number=input_data_hep['report_number']
    )
    builder.add_collaboration(collaboration=input_data_hep['collaboration'])
    builder.add_acquisition_source(
        method=input_data_hep['method'],
        submission_number=input_data_hep['submission_number'],
        internal_uid=input_data_hep['internal_uid'],
        email=input_data_hep['email'],
        orcid=input_data_hep['orcid']
    )
    builder.add_document_type(document_type=input_data_hep['document_type'])
    builder.add_copyright(
        material=input_data_hep['material'],
        holder=input_data_hep['holder'],
        statement=input_data_hep['statement'],
        url=input_data_hep['copyright_url']
    )
    builder.add_number_of_pages(
        number_of_pages=input_data_hep['number_of_pages']
    )
    builder.add_special_collection(
        special_collection=input_data_hep['special_collection']
    )
    builder.add_publication_type(
        publication_type=input_data_hep['publication_type']
    )
    builder.add_book_edition(
        edition=input_data_hep['book_edition']
    )
    builder.add_book(
        publisher=input_data_hep['publisher'],
        place=input_data_hep['place'],
        date=input_data_hep['imprint_date']
    )
    builder.add_book_series(
        title=input_data_hep['title'],
        volume=input_data_hep['book_volume']
    )
    builder.add_isbns(
        isbn=input_data_hep['isbn']
    )
    builder.set_core(core=input_data_hep['core'])
    builder.set_refereed(refereed=input_data_hep['refereed'])
    builder.set_withdrawn(withdrawn=input_data_hep['withdrawn'])
    builder.set_citeable(citeable=input_data_hep['citeable'])
    assert builder.validate_record() is None
    assert builder.record == expected_data_hep
