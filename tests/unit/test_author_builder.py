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

from __future__ import absolute_import, division, print_function

from inspire_schemas.api import load_schema, validate
from inspire_schemas.builders.authors import AuthorBuilder


def test_author_builder_default_constructor():
    expected = {
        '_collections': ['Authors'],
    }
    result = AuthorBuilder()

    assert expected == result.obj


def test_author_builder_copy_constructor():
    expected = {'name': {'value': 'Torre, Riccardo'}}
    result = AuthorBuilder({'name': {'value': 'Torre, Riccardo'}})

    assert expected == result.obj


def test_author_builder_set_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_author_builder_set_name_normalizes_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Riccardo Torre')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_author_builder_set_name_can_be_called_multiple_times():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Richard Tower')
    author.set_name('Riccardo Torre')

    expected = {'value': 'Torre, Riccardo'}
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_set_display_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')
    author.set_display_name('Rick')

    expected = {
        'value': 'Torre, Riccardo',
        'preferred_name': 'Rick'
    }
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_set_display_name_can_be_called_multiple_times():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')
    author.set_display_name('Ricardo')
    author.set_display_name('Rick')

    expected = {
        'value': 'Torre, Riccardo',
        'preferred_name': 'Rick'
    }
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_native_name():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')
    author.add_native_name('Rick')

    expected = {
        'value': 'Torre, Riccardo',
        'native_names': [
            'Rick'
        ]
    }
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_multiple_native_names():
    schema = load_schema('authors')
    subschema = schema['properties']['name']

    author = AuthorBuilder()
    author.set_name('Torre, Riccardo')
    author.add_native_name('Rick')
    author.add_native_name('Torrecillas')
    author.add_native_name('Ricardo')

    expected = {
        'value': 'Torre, Riccardo',
        'native_names': [
            'Rick',
            'Torrecillas',
            'Ricardo',
        ]
    }
    result = author.obj['name']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_email_address():
    schema = load_schema('authors')
    subschema = schema['properties']['email_addresses']

    author = AuthorBuilder()
    author.add_email_address('example@test.com')

    expected = [{
        "value": 'example@test.com'
    }]
    result = author.obj['email_addresses']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_multiple_email_addresses():
    schema = load_schema('authors')
    subschema = schema['properties']['email_addresses']

    author = AuthorBuilder()
    author.add_email_address('example@test.com')
    author.add_email_address('test@example.com')

    expected = [{
        "value": 'example@test.com'
    },
        {
        "value": 'test@example.com'
    }]
    result = author.obj['email_addresses']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_email_addresses_skips_duplicate_ones():
    schema = load_schema('authors')
    subschema = schema['properties']['email_addresses']

    author = AuthorBuilder()
    author.add_email_address('example@test.com')
    author.add_email_address('example@test.com')

    expected = [{
        "value": 'example@test.com'
    }]
    result = author.obj['email_addresses']

    assert validate(result, subschema) is None
    assert expected == result


def test_set_status():
    schema = load_schema('authors')
    subschema = schema['properties']['status']

    author = AuthorBuilder()
    author.set_status('active')

    expected = 'active'
    result = author.obj['status']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_without_description():
    schema = load_schema('authors')
    subschema = schema['properties']['urls']

    author = AuthorBuilder()
    author.add_url('https://www.example.com')

    expected = [{
        "value": "https://www.example.com"
    }]
    result = author.obj['urls']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_with_description():
    schema = load_schema('authors')
    subschema = schema['properties']['urls']

    author = AuthorBuilder()
    author.add_url('https://www.example.com', 'this is an example')

    expected = [{
        "value": "https://www.example.com",
        "description": "this is an example"
    }]
    result = author.obj['urls']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_blog():
    schema = load_schema('authors')
    subschema = schema['properties']['urls']

    author = AuthorBuilder()
    author.add_blog('https://www.blog.com')

    expected = [{
        "value": "https://www.blog.com",
        "description": "blog"
    }]
    result = author.obj['urls']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_linkedin():
    schema = load_schema('authors')
    subschema = schema['properties']['ids']

    author = AuthorBuilder()
    author.add_linkedin('https://www.linkedin.com/in/example-12345/')

    expected = [{
        "value": "https://www.linkedin.com/in/example-12345/",
        "schema": "LINKEDIN"
    }]
    result = author.obj['ids']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_twitter():
    schema = load_schema('authors')
    subschema = schema['properties']['ids']

    author = AuthorBuilder()
    author.add_twitter('https://twitter.com/Example')

    expected = [{
        "value": "https://twitter.com/Example",
        "schema": "TWITTER"
    }]
    result = author.obj['ids']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_orcid():
    schema = load_schema('authors')
    subschema = schema['properties']['ids']

    author = AuthorBuilder()
    author.add_orcid('0000-0002-7638-5686')

    expected = [{
        "value": "0000-0002-7638-5686",
        "schema": "ORCID"
    }]
    result = author.obj['ids']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_arxiv_category():
    schema = load_schema('authors')
    subschema = schema['properties']['arxiv_categories']

    author = AuthorBuilder()
    author.add_arxiv_category('math.CV')

    expected = [
        "math.CV"
    ]
    result = author.obj['arxiv_categories']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_arxiv_category_accepts_multiple_categories():
    schema = load_schema('authors')
    subschema = schema['properties']['arxiv_categories']

    author = AuthorBuilder()
    author.add_arxiv_category('math.CV')
    author.add_arxiv_category('astro-ph.HE')
    author.add_arxiv_category('econ.EM')

    expected = [
        "math.CV",
        "astro-ph.HE",
        "econ.EM",
    ]
    result = author.obj['arxiv_categories']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='Colgate University',
                           start_date='1994-02-01',
                           end_date='1995-01-31',
                           rank='PHD',
                           record={
                                "$ref": "http://180"
                           },
                           curated=True,
                           current=False)

    expected = [{
        "institution": 'Colgate University',
        "start_date": u'1994-02-01',
        "end_date": u'1995-01-31',
        "rank": 'PHD',
        "record": {
            "$ref": "http://180"
        },
        "curated_relation": True,
        "current": False
    }]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_sorts_by_current():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='Colgate University',
                           start_date='1994-02-01')
    author.add_institution(institution='First University',
                           start_date='1950-02-01',
                           current=True)

    expected = [
        {
            "institution": 'First University',
            "start_date": u'1950-02-01',
            "curated_relation": False,
            "current": True
        },
        {
            "institution": 'Colgate University',
            "start_date": u'1994-02-01',
            "curated_relation": False,
            "current": False
        },
    ]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_sorts_by_start_date():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='First University',
                           start_date='1950-02-01')
    author.add_institution(institution='Dateless University')
    author.add_institution(institution='Colgate University',
                           start_date='1994-02-01')

    expected = [
        {
            "institution": 'Colgate University',
            "start_date": u'1994-02-01',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'First University',
            "start_date": u'1950-02-01',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Dateless University',
            "curated_relation": False,
            "current": False
        }
    ]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_sorts_by_rank():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='Colgate University',
                           rank='MASTER')
    author.add_institution(institution='Colgate University',
                           rank='PHD')
    author.add_institution(institution='Colgate University',
                           rank='VISITOR')
    author.add_institution(institution='Colgate University',
                           rank='STAFF')
    author.add_institution(institution='Colgate University',
                           rank='SENIOR')
    author.add_institution(institution='Colgate University',
                           rank='OTHER')
    author.add_institution(institution='Colgate University',
                           rank='UNDERGRADUATE')
    author.add_institution(institution='Colgate University')
    author.add_institution(institution='Colgate University',
                           rank='POSTDOC')
    author.add_institution(institution='Colgate University',
                           rank='JUNIOR')

    expected = [
        {
            "institution": 'Colgate University',
            "rank": 'STAFF',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'SENIOR',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'JUNIOR',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'VISITOR',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'POSTDOC',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'PHD',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'MASTER',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'UNDERGRADUATE',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "rank": 'OTHER',
            "curated_relation": False,
            "current": False
        },
        {
            "institution": 'Colgate University',
            "curated_relation": False,
            "current": False
        },
    ]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_normalizes_start_date():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='Colgate University',
                           start_date='February 1 1994')

    expected = [{
        "institution": 'Colgate University',
        "start_date": u'1994-02-01',
        "curated_relation": False,
        "current": False
    }]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_normalizes_end_date():
    schema = load_schema('authors')
    subschema = schema['properties']['positions']

    author = AuthorBuilder()
    author.add_institution(institution='Colgate University',
                           end_date='31 January 2005')

    expected = [{
        "institution": 'Colgate University',
        "end_date": u'2005-01-31',
        "curated_relation": False,
        "current": False
    }]
    result = author.obj['positions']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_project():
    schema = load_schema('authors')
    subschema = schema['properties']['project_membership']

    author = AuthorBuilder()
    author.add_project(name='pariatur',
                       start_date='1997-05-01',
                       end_date='2001-12-31',
                       record={
                            "$ref": "http://180"
                       },
                       curated=True,
                       current=True)

    expected = [{
        "name": 'pariatur',
        "start_date": u'1997-05-01',
        "end_date": u'2001-12-31',
        "record": {
            "$ref": "http://180"
        },
        "curated_relation": True,
        "current": True
    }]
    result = author.obj['project_membership']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_project_sorts_by_current():
    schema = load_schema('authors')
    subschema = schema['properties']['project_membership']

    author = AuthorBuilder()
    author.add_project(name='pariatur',
                       start_date='1997-05-01')
    author.add_project(name='current one',
                       start_date='1949-05-01',
                       current=True)

    expected = [
        {
            'name': 'current one',
            'start_date': '1949-05-01',
            'curated_relation': False,
            'current': True,
        },
        {
            'name': 'pariatur',
            'start_date': u'1997-05-01',
            'curated_relation': False,
            'current': False,
        }
    ]
    result = author.obj['project_membership']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_project_sorts_by_start_date():
    schema = load_schema('authors')
    subschema = schema['properties']['project_membership']

    author = AuthorBuilder()
    author.add_project(name='earliest one',
                       start_date='1949-05-01')
    author.add_project(name='pariatur',
                       start_date='1997-05-01')

    expected = [
        {
            'name': 'pariatur',
            'start_date': u'1997-05-01',
            'curated_relation': False,
            'current': False,
        },
        {
            'name': 'earliest one',
            'start_date': '1949-05-01',
            'curated_relation': False,
            'current': False,
        },
    ]
    result = author.obj['project_membership']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_project_normalizes_start_date():
    schema = load_schema('authors')
    subschema = schema['properties']['project_membership']

    author = AuthorBuilder()
    author.add_project(name='pariatur',
                       start_date='1999 February')

    expected = [{
        "name": 'pariatur',
        "start_date": u'1999-02',
        "curated_relation": False,
        "current": False
    }]
    result = author.obj['project_membership']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_institution_normalizes_end_date():
    schema = load_schema('authors')
    subschema = schema['properties']['project_membership']

    author = AuthorBuilder()
    author.add_project(name='pariatur',
                       end_date='5 2016 January')

    expected = [{
        "name": 'pariatur',
        "end_date": u'2016-01-05',
        "curated_relation": False,
        "current": False
    }]
    result = author.obj['project_membership']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_private_note():
    schema = load_schema('authors')
    subschema = schema['properties']['_private_notes']

    author = AuthorBuilder()
    author.add_private_note(note='this is an example',
                            source='curator')

    expected = [{
        "value": 'this is an example',
        "source": 'curator'
    }]
    result = author.obj['_private_notes']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_private_note_without_source():
    schema = load_schema('authors')
    subschema = schema['properties']['_private_notes']

    author = AuthorBuilder()
    author.add_private_note('this is an example')

    expected = [{
        "value": 'this is an example'
    }]
    result = author.obj['_private_notes']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_advisor():
    schema = load_schema('authors')
    subschema = schema['properties']['advisors']

    author = AuthorBuilder()
    author.add_advisor(name='Torres, Riccardo',
                       ids=[{
                            "schema": "DESY",
                            "value": "DESY-55924820881"
                            },
                            {
                            "schema": "SCOPUS",
                            "value": "7039712595"
                            },
                            {
                            "schema": "SCOPUS",
                            "value": "8752067273"
                            }],
                       degree_type='bachelor',
                       record={
                           "$ref": "http://180"
                       },
                       curated=True)

    expected = [{
        "name": 'Torres, Riccardo',
        "ids": [{
            "schema": "DESY",
            "value": "DESY-55924820881"
        },
            {
            "schema": "SCOPUS",
            "value": "7039712595"
        },
            {
            "schema": "SCOPUS",
            "value": "8752067273"
        }],
        "degree_type": 'bachelor',
        "record": {
            "$ref": "http://180"
        },
        "curated_relation": True
    }]
    result = author.obj['advisors']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_advisor_normalizes_name():
    schema = load_schema('authors')
    subschema = schema['properties']['advisors']

    author = AuthorBuilder()
    author.add_advisor('Riccardo Torres Jr')

    expected = [{
        "name": 'Torres, Riccardo, Jr.',
        "curated_relation": False
    }]
    result = author.obj['advisors']

    assert validate(result, subschema) is None
    assert expected == result


def test_add_acquisition_source():
    schema = load_schema('authors')
    subschema = schema['properties']['acquisition_source']
    author = AuthorBuilder()
    author.add_acquisition_source(
        method='submitter',
        submission_number='12',
        internal_uid=1,
        email='albert.einstein@hep.edu',
        orcid='0000-0001-8528-2091',
    )

    expected = {
        'method': 'submitter',
        'submission_number': '12',
        'internal_uid': 1,
        'email': 'albert.einstein@hep.edu',
        'orcid': '0000-0001-8528-2091',
    }
    result = author.obj['acquisition_source']

    assert validate(result, subschema) is None
    assert expected == result
