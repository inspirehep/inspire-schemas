# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016-2024 CERN.
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

import json
import os

import pytest
import yaml

from inspire_schemas import api
from inspire_schemas.builders import ConferenceBuilder, DataBuilder, JobBuilder, SeminarBuilder

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), 'fixtures')


def load_file(file_name):
    path = os.path.join(FIXTURES_PATH, file_name)
    with open(path) as input_data:
        data = yaml.full_load(input_data.read())

    return data


def load_json_file(file_name):
    path = os.path.join(FIXTURES_PATH, file_name)
    with open(path) as input_data:
        data = json.load(input_data)

    return data


@pytest.fixture(scope='module')
def expected_data_hep():
    return load_file('expected_data_hep.yaml')


@pytest.fixture(scope='module')
def input_data_hep():
    return load_file('input_data_hep.yaml')

@pytest.fixture(scope='module')
def conference_data():
    return load_json_file('conferences_example.json')


@pytest.fixture(scope='module')
def seminar_data():
    return load_json_file('seminars_example.json')


@pytest.fixture(scope='module')
def job_data():
    return load_json_file('jobs_example.json')


@pytest.fixture(scope='module')
def data_data():
    return load_json_file('data_example.json')


def test_literature_builder_valid_record(input_data_hep, expected_data_hep):

    builder = api.LiteratureBuilder('submitter')

    builder.add_abstract(
        abstract=input_data_hep['abstract'],
    )
    builder.add_arxiv_eprint(
        arxiv_id=input_data_hep['arxiv_id'],
        arxiv_categories=input_data_hep['arxiv_categories'],
    )
    builder.add_doi(doi=input_data_hep['doi'], material=input_data_hep['material'])
    author = builder.make_author(
        full_name=input_data_hep['full_name'],
        affiliations=input_data_hep['affiliations'],
        roles=input_data_hep['roles'],
        raw_affiliations=input_data_hep['raw_affiliations'],
        affiliations_identifiers=input_data_hep['affiliations_identifiers'],
    )
    builder.add_author(author)

    builder.add_inspire_categories(
        subject_terms=input_data_hep['subject_terms'],
        source=input_data_hep['source_categories'],
    )
    builder.add_private_note(private_notes=input_data_hep['private_notes'])
    builder.add_publication_info(
        year=input_data_hep['year'],
        cnum=input_data_hep['cnum'],
        artid=input_data_hep['artid'],
        page_end=input_data_hep['page_end'],
        page_start=input_data_hep['page_start'],
        journal_issue=input_data_hep['journal_issue'],
        journal_title=input_data_hep['journal_title'],
        journal_volume=input_data_hep['journal_volume'],
        material=input_data_hep['material'],
        parent_record=input_data_hep['parent_record'],
        parent_isbn=input_data_hep['parent_isbn'],
    )
    builder.add_preprint_date(preprint_date=input_data_hep['preprint_date'])
    builder.add_thesis(
        defense_date=input_data_hep['defense_date'],
        degree_type=input_data_hep['degree_type'],
        institution=input_data_hep['institution'],
        date=input_data_hep['date'],
    )
    builder.add_accelerator_experiments_legacy_name(
        legacy_name=input_data_hep['legacy_name']
    )
    builder.add_language(language=input_data_hep['language'])
    builder.add_license(
        url=input_data_hep['license_url'],
        license=input_data_hep['license'],
        imposing=input_data_hep['license_imposing'],
        material=input_data_hep['material'],
    )
    builder.add_public_note(public_note=input_data_hep['public_note'])
    builder.add_title(
        title=input_data_hep['title'],
        subtitle=input_data_hep['subtitle'],
    )
    builder.add_title_translation(
        title=input_data_hep['title'], language=input_data_hep['language']
    )
    builder.add_url(url=input_data_hep['url'])
    builder.add_report_number(report_number=input_data_hep['report_number'])
    builder.add_collaboration(collaboration=input_data_hep['collaboration'])
    builder.add_acquisition_source(
        method=input_data_hep['method'],
        submission_number=input_data_hep['submission_number'],
        internal_uid=input_data_hep['internal_uid'],
        email=input_data_hep['email'],
        orcid=input_data_hep['orcid'],
    )
    builder.add_document_type(document_type=input_data_hep['document_type'])
    builder.add_copyright(
        material=input_data_hep['material'],
        year=input_data_hep['year'],
        holder=input_data_hep['holder'],
        statement=input_data_hep['statement'],
        url=input_data_hep['copyright_url'],
    )
    builder.add_number_of_pages(number_of_pages=input_data_hep['number_of_pages'])
    builder.add_collection(collection=input_data_hep['collection'])
    builder.add_publication_type(publication_type=input_data_hep['publication_type'])
    builder.add_book_edition(edition=input_data_hep['book_edition'])
    builder.add_book(
        publisher=input_data_hep['publisher'],
        place=input_data_hep['place'],
        date=input_data_hep['imprint_date'],
    )
    builder.add_book_series(
        title=input_data_hep['title'], volume=input_data_hep['book_volume']
    )
    for isbn in input_data_hep['isbns']:
        builder.add_isbn(isbn=isbn['code'], medium=isbn['type_of_isbn'])
    builder.set_core(core=input_data_hep['core'])
    builder.set_refereed(refereed=input_data_hep['refereed'])
    builder.set_withdrawn(withdrawn=input_data_hep['withdrawn'])
    builder.set_citeable(citeable=input_data_hep['citeable'])
    builder.set_curated(curated=input_data_hep['curated'])
    assert builder.validate_record() is None
    assert builder.record == expected_data_hep


def test_literature_and_reference_builder():
    hep_builder = api.LiteratureBuilder()
    hep_builder.add_document_type('article')
    hep_builder.add_title('Work Title')

    ref_builder = api.ReferenceBuilder()
    ref_builder.add_title('Cited Work')
    ref_builder.add_author('Smith, J.', 'author')

    hep_builder.add_reference(ref_builder.obj)

    assert hep_builder.validate_record() is None


def test_job_builder(job_data):
    start_data = {
        '_collections': ['Jobs'],
        'control_number': job_data['control_number'],
        'deleted': job_data['deleted'],
        'deleted_records': job_data['deleted_records'],
        'legacy_creation_date': job_data['legacy_creation_date'],
        'legacy_version': job_data['legacy_version'],
        'new_record': job_data['new_record'],
        'public_notes': job_data['public_notes'],
        'self': job_data['self'],
    }
    builder = JobBuilder(start_data)

    private_note = job_data['_private_notes']
    builder.add_private_note(**private_note[0])
    assert builder.record['_private_notes'] == private_note

    experiments = job_data['accelerator_experiments']
    builder.add_accelerator_experiment(**experiments[0])
    builder.add_accelerator_experiment(**experiments[1])
    assert builder.record['accelerator_experiments'] == experiments

    acquisition_source = job_data['acquisition_source']
    builder.add_acquisition_source(**acquisition_source)
    assert builder.record['acquisition_source'] == acquisition_source

    arxiv = job_data['arxiv_categories']
    builder.add_arxiv_category(arxiv[0])
    builder.add_arxiv_category(arxiv[1])
    builder.add_arxiv_category(arxiv[2])
    assert builder.record['arxiv_categories'] == arxiv

    contact_details = job_data['contact_details']
    builder.add_contact(**contact_details[0])
    builder.add_contact(**contact_details[1])
    builder.add_contact(**contact_details[2])
    assert builder.record['contact_details'] == contact_details

    deadline = job_data['deadline_date']
    builder.set_deadline(deadline)
    assert builder.record['deadline_date'] == deadline

    description = job_data['description']
    builder.set_description(description)
    assert builder.record['description'] == description

    external_job_id = job_data['external_job_identifier']
    builder.set_external_job_identifier(external_job_id)
    assert builder.record['external_job_identifier'] == external_job_id

    external_system_id = job_data['external_system_identifiers']
    builder.add_external_system_identifiers(**external_system_id[0])
    assert builder.record['external_system_identifiers'] == external_system_id

    institutions = job_data['institutions']
    builder.add_institution(**institutions[0])
    builder.add_institution(**institutions[1])
    assert builder.record['institutions'] == institutions

    position = job_data['position']
    builder.set_title(position)
    assert builder.record['position'] == position

    ranks = job_data['ranks']
    builder.add_rank(ranks[0])
    assert builder.record['ranks'] == ranks

    ref_letters = job_data['reference_letters']
    builder.add_reference_email(ref_letters['emails'][0])
    builder.add_reference_email(ref_letters['emails'][1])
    builder.add_reference_url(**ref_letters['urls'][0])
    builder.add_reference_url(**ref_letters['urls'][1])
    builder.add_reference_url(**ref_letters['urls'][2])
    builder.add_reference_url(**ref_letters['urls'][3])
    builder.add_reference_url(**ref_letters['urls'][4])
    assert builder.record['reference_letters'] == ref_letters

    regions = job_data['regions']
    builder.add_region(regions[0])
    builder.add_region(regions[1])
    builder.add_region(regions[2])
    builder.add_region(regions[3])
    assert builder.record['regions'] == regions

    status = job_data['status']
    builder.set_status(status)
    assert builder.record['status'] == status

    urls = job_data['urls']
    builder.add_url(**urls[0])
    builder.add_url(**urls[1])
    assert builder.record['urls'] == urls

    assert builder.record == job_data

    builder.validate_record()


def test_conference_builder(conference_data):
    builder = ConferenceBuilder()

    private_notes = conference_data['_private_notes']
    builder.add_private_note(**private_notes[0])
    builder.add_private_note(**private_notes[1])
    builder.add_private_note(**private_notes[2])
    builder.add_private_note(**private_notes[3])

    builder.add_acronym(conference_data['acronyms'][0])

    builder.add_address(**conference_data['addresses'][0])

    alternative_titles = conference_data['alternative_titles']
    builder.add_alternative_title(**alternative_titles[0])
    builder.add_alternative_title(**alternative_titles[1])
    builder.add_alternative_title(**alternative_titles[2])

    builder.set_cnum(cnum=conference_data['cnum'])

    contact_details = conference_data['contact_details']
    builder.add_contact(**contact_details[0])
    builder.add_contact(**contact_details[1])
    builder.add_contact(**contact_details[2])
    builder.add_contact(**contact_details[3])

    builder.set_core(conference_data['core'])

    external_ids = conference_data['external_system_identifiers']
    builder.add_external_system_identifier(**external_ids[0])
    builder.add_external_system_identifier(**external_ids[1])
    builder.add_external_system_identifier(**external_ids[2])
    builder.add_external_system_identifier(**external_ids[3])

    inspire_cats = ["Gravitation and Cosmology", "General Physics"]
    builder.add_inspire_categories(subject_terms=inspire_cats, source="user")
    builder.add_inspire_categories(
        subject_terms=["Math and Math Physics"], source="curator"
    )
    builder.add_inspire_categories(subject_terms=["Astrophysics"], source="magpie")

    keywords = conference_data['keywords']
    builder.add_keyword(**keywords[0])
    builder.add_keyword(**keywords[1])

    public_notes = conference_data['public_notes']
    builder.add_public_note(**public_notes[0])
    builder.add_public_note(**public_notes[1])
    builder.add_public_note(**public_notes[2])
    builder.add_public_note(**public_notes[3])

    series = conference_data['series']
    builder.add_series(**series[0])
    builder.add_series(**series[1])

    builder.set_short_description(**conference_data['short_description'])

    builder.set_closing_date(conference_data['closing_date'])
    builder.set_opening_date(conference_data['opening_date'])

    titles = conference_data['titles']
    for title in titles:
        builder.add_title(**title)

    urls = conference_data['urls']
    for url in urls:
        builder.add_url(**url)

    builder.validate_record()

    assert builder.record == conference_data


def test_seminar_builder(seminar_data):
    start_data = {
        '_collections': seminar_data['_collections'],
        '_private_notes': seminar_data['_private_notes'],
        'captioned': seminar_data["captioned"],
        'control_number': seminar_data['control_number'],
        'deleted': seminar_data['deleted'],
        'core': seminar_data['core'],
        'deleted_records': seminar_data['deleted_records'],
        'acquisition_source': seminar_data['acquisition_source'],
        'new_record': seminar_data['new_record'],
        'public_notes': seminar_data['public_notes'],
        'self': seminar_data['self'],
    }
    builder = SeminarBuilder(start_data)

    address = seminar_data['address']
    builder.set_address(**address)

    contact_details = seminar_data['contact_details']
    for contact in contact_details:
        builder.add_contact(**contact)

    inspire_categories = seminar_data['inspire_categories']
    for category in inspire_categories:
        builder.add_inspire_categories(
            subject_terms=[category['term']], source=category.get('source')
        )

    keywords = seminar_data['keywords']
    for keyword in keywords:
        builder.add_keyword(**keyword)

    speakers = seminar_data['speakers']
    for speaker in speakers:
        builder.add_speaker(**speaker)

    public_notes = seminar_data['public_notes']
    for note in public_notes:
        builder.add_public_note(**note)

    series = seminar_data['series']
    for serie in series:
        builder.add_series(**serie)

    builder.set_abstract(**seminar_data['abstract'])

    builder.set_end_datetime(seminar_data['end_datetime'])
    builder.set_start_datetime(seminar_data['start_datetime'])
    builder.set_timezone(seminar_data['timezone'])

    title = seminar_data['title']
    builder.set_title(**title)

    urls = seminar_data['urls']
    for url in urls:
        builder.add_url(**url)

    join_urls = seminar_data['join_urls']
    for url in join_urls:
        builder.add_join_url(**url)

    material_urls = seminar_data["material_urls"]
    for url in material_urls:
        builder.add_material_url(**url)

    builder.validate_record()

    assert builder.record == seminar_data


def test_data_builder(data_data):
    start_data = {
        '_bucket': data_data['_bucket'],
        '_collections': data_data['_collections'][0],
        'control_number': data_data['control_number'],
        'deleted': data_data['deleted'],
        'deleted_records': data_data['deleted_records'],
        'creation_date': data_data['creation_date'],
        'legacy_version': data_data['legacy_version'],
        'new_record': data_data['new_record'],
        'self': data_data['self'],
    }
    builder = DataBuilder(start_data)

    dois = data_data['dois']
    for doi in dois:
        builder.add_doi(doi['value'], doi['source'])
    assert builder.record['dois'] == dois

    collaborations = data_data['collaborations']
    for collaboration in collaborations:
        builder.add_collaboration(collaboration['value'])
    assert len(builder.record['collaborations']) == len(collaborations)

    accelerator_experiments = data_data['accelerator_experiments']
    for experiment in accelerator_experiments:
        builder.add_accelerator_experiment(experiment['legacy_name'])
    assert len(builder.record['accelerator_experiments']) == len(accelerator_experiments)

    abstracts = data_data['abstracts']
    for abstract in abstracts:
        builder.add_abstract(abstract["value"], abstract["source"])
    assert builder.record['abstracts'] == abstracts

    keywords = data_data['keywords']
    for keyword in keywords:
        builder.add_keyword(keyword=keyword['value'], source=keyword['source'])
    assert builder.record['keywords'] == keywords

    literatures = data_data['literature']
    for literature in literatures:
        builder.add_literature(literature.get("doi"), literature.get('record'))
    assert builder.record['literature'] == literatures

    urls = data_data['urls']
    for url in urls:
        builder.add_url(**url)
    assert builder.record['urls'] == urls

    titles = data_data['titles']
    for title in titles:
        builder.add_title(**title)
    assert builder.record['titles'] == titles

    acquisition_source = data_data['acquisition_source']
    builder.add_acquisition_source(**acquisition_source)
    assert builder.record['acquisition_source'] == acquisition_source

    authors = data_data['authors']
    for author in authors:
        builder.add_author(author)
    assert builder.record['authors'] == authors

    builder.validate_record()
