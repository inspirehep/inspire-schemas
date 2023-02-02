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

from inspire_schemas.utils import load_schema, validate
from inspire_schemas.builders.references import (
    ReferenceBuilder,
    _split_refextract_authors_str,
)


def test_set_label():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_label('Abe et al, 2008')

    expected = [
        {
            'reference': {
                'label': 'Abe et al, 2008',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_record():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    ref = {
        '$ref': 'http://localhost:5000/api/literature/1226234',
    }

    builder.set_record(ref)

    expected = [
        {
            'curated_relation': False,
            'record': {
                '$ref': 'http://localhost:5000/api/literature/1226234',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_curate():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.curate()

    expected = [
        {'curated_relation': True},
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_texkey():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_texkey('Aaij:2016qlz')

    expected = [
        {
            'reference': {
                'texkey': 'Aaij:2016qlz',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_title():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_title('The CMS experiment at the CERN LHC')

    expected = [
        {
            'reference': {
                'title': {
                    'title': 'The CMS experiment at the CERN LHC',
                }
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_parent_title():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_parent_title('Geom. Funct. Anal., GAFA 2000')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'parent_title': 'Geom. Funct. Anal., GAFA 2000',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_misc():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_misc('[Erratum:')

    expected = [
        {
            'reference': {
                'misc': [
                    '[Erratum:',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_misc_with_dupes():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_misc('[Erratum:')
    builder.add_misc('[Erratum:')

    expected = [
        {
            'reference': {
                'misc': [
                    '[Erratum:',
                    '[Erratum:',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_raw_reference_no_source():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_raw_reference('Phys. Rev. C 80 (doi:10.1103/'
                              'PhysRevC.80.044313)')

    expected = [
        {
            'raw_refs': [
                {
                    'schema': 'text',
                    'value': 'Phys. Rev. C 80 (doi:10.1103/'
                             'PhysRevC.80.044313)',
                },
            ],
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_raw_reference_with_source():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_raw_reference('Phys. Rev. C 80 (doi:10.1103/'
                              'PhysRevC.80.044313)', 'arXiv')

    expected = [
        {
            'raw_refs': [
                {
                    'schema': 'text',
                    'source': 'arXiv',
                    'value': 'Phys. Rev. C 80 (doi:10.1103/'
                             'PhysRevC.80.044313)',
                },
            ],
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_year():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_year(2017)

    expected = [
        {
            'reference': {
                'publication_info': {
                    'year': 2017,
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_year_rejects_malformed_years():
    builder = ReferenceBuilder()

    builder.set_year('foobar')

    expected = [{}]
    result = [builder.obj]

    assert expected == result


def test_set_year_rejects_invalid_years():
    builder = ReferenceBuilder()

    builder.set_year(666)

    expected = [{}]
    result = [builder.obj]

    assert expected == result

    builder.set_year(2112)

    expected = [{}]
    result = [builder.obj]

    assert expected == result


def test_add_url():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('http://www.muonsinc.com')

    expected = [
        {
            'reference': {
                'urls': [
                    {'value': 'http://www.muonsinc.com'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_uses_fix_url():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('www.muonsinc.com')

    expected = [
        {
            'reference': {
                'urls': [
                    {'value': 'http://www.muonsinc.com'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_adds_uid():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('10.1109/NSSMIC.2005.1596597')
    builder.add_url('https://doi.org/10.1109/NSSMIC.2005.1596597')

    expected = [
        {
            'reference': {
                'dois': [
                    '10.1109/NSSMIC.2005.1596597'
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_refextract_author_str():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_refextract_authors_str('S. Frixione, P. Nason, and C. Oleari')

    expected = [
        {
            'reference': {
                'authors': [
                    {'full_name': 'Frixione, S.'},
                    {'full_name': 'Nason, P.'},
                    {'full_name': 'Oleari, C.'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_refextract_authors_str_noninitials():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_refextract_authors_str(
        'Igor R. Klebanov and Juan Martin Maldacena'
    )

    expected = [
        {
            'reference': {
                'authors': [
                    {'full_name': 'Klebanov, Igor R.'},
                    {'full_name': 'Maldacena, Juan Martin'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_refextract_authors_str_discards_et_al():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_refextract_authors_str(
        'S. B. Cenko, M. M. Kasliwal, D. A. Perley et al.'
    )

    expected = [
        {
            'reference': {
                'authors': [
                    {'full_name': 'Cenko, S.B.'},
                    {'full_name': 'Kasliwal, M.M.'},
                    {'full_name': 'Perley, D.A.'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_refextract_authors_str_unicode():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_refextract_authors_str(u'Kätlne, J.')

    expected = [
        {
            'reference': {
                'authors': [
                    {'full_name': u'Kätlne, J.'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_author():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_author('Cox, Brian')

    expected = [
        {
            'reference': {
                'authors': [
                    {'full_name': 'Cox, Brian'},
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_author_handles_inspire_role():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_author("O'Brian, Dara", 'ed.')

    expected = [
        {
            'reference': {
                'authors': [
                    {
                        'full_name': "O'Brian, Dara",
                        'inspire_role': 'editor',
                    },
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_pubnote():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_pubnote('Nucl.Phys.,B360,362')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'artid': '362',
                    'journal_title': 'Nucl.Phys.B',
                    'journal_volume': '360',
                    'page_start': '362',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_pubnote_falls_back_to_misc():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_pubnote('not-a-valid-pubnote')

    expected = [
        {
            'reference': {
                'misc': ['not-a-valid-pubnote'],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_pubnote_does_not_overwrite_pubnote():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_pubnote('Phys.Rev.,D43,124-156')
    builder.set_pubnote(',12,18')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'Phys.Rev.D',
                    'journal_volume': '43',
                    'page_start': '124',
                    'page_end': '156',
                },
                'misc': ['Additional pubnote: ,12,18'],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_pubnote_puts_incomplete_pubnote_in_misc():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_pubnote('Phys.Rev.,D43,')

    expected = [
        {
            'reference': {
                'misc': ['Phys.Rev.,D43,']
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_publisher():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_publisher('Elsevier')

    expected = [
        {
            'reference': {
                'imprint': {
                    'publisher': 'Elsevier',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_imprint_date():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_imprint_date('23/12/2015')

    expected = [
        {
            'reference': {
                'imprint': {
                    'date': '2015-12-23',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_imprint_place():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_imprint_place('New York')

    expected = [
        {
            'reference': {
                'imprint': {
                    'place': 'New York',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_report_number_handles_several_report_numbers():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_report_number('CMS-B2G-17-001')
    builder.add_report_number('CERN-EP-2017-184')

    expected = [
        {
            'reference': {
                'report_numbers': [
                    'CMS-B2G-17-001',
                    'CERN-EP-2017-184',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_report_number_handles_arxiv_ids():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_report_number('hep-th/0603001')

    expected = [
        {
            'reference': {
                'arxiv_eprint': 'hep-th/0603001',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_handles_arxiv_ids():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('hep-th/0603001')

    expected = [
        {
            'reference': {
                'arxiv_eprint': 'hep-th/0603001',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_handles_dois():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('http://dx.doi.org/10.3972/water973.0145.db')

    expected = [
        {
            'reference': {
                'dois': [
                    '10.3972/water973.0145.db',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_handles_handles():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('hdl:10443/1646')

    expected = [
        {
            'reference': {
                'persistent_identifiers': [
                    {
                        'schema': 'HDL',
                        'value': '10443/1646',
                    },
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_handles_cnums():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('C87-11-11')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'cnum': 'C87-11-11',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_handles_ads_ids():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('http://adsabs.harvard.edu/abs/2018ApJ...853...70U')

    expected = [
        {
            'reference': {
                'external_system_identifiers': [{
                    'schema': 'ADS',
                    'value': '2018ApJ...853...70U',
                }],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_handles_cds_ids():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('http://cds.cern.ch/record/2310556?ln=en')
    builder.add_url('http://cds.cern.ch/record/2310556?ln=fr')

    expected = [
        {
            'reference': {
                'external_system_identifiers': [{
                    'schema': 'CDS',
                    'value': '2310556',
                }],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_falls_back_to_isbn():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('1449344852')

    expected = [
        {
            'reference': {
                'isbn': '9781449344856',
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_uid_rejects_invalid_isbns():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('123456789')

    expected = [
        {
            'reference': {
                'misc': [
                    '123456789',
                ]
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_collaboration():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_collaboration('ALICE')

    expected = [
        {
            'reference': {
                'collaborations': [
                    'ALICE',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_journal_title():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_journal_title('Phys. Rev. D')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'Phys. Rev. D'
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_journal_issue():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_journal_issue('12')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_issue': '12'
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_journal_volume():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_journal_volume('2016')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_volume': '2016'
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_page_artid():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_page_artid('12', '13', '014568')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'page_start': '12',
                    'page_end': '13',
                    'artid': '014568',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_set_page_artid_none():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.set_page_artid(None, None, '014568')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'artid': '014568',
                },
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_is_arxiv_matches_valid_categories():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_uid('BF/0234502')
    builder.add_uid('math/0311149')

    expected = [
        {
            'reference': {
                'persistent_identifiers': [{
                    'value': 'BF/0234502',
                    'schema': 'HDL',
                }],
                'arxiv_eprint': 'math/0311149'
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_rejects_empty_cds_id():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('https://cds.cern.ch/record/')

    expected = [
        {
            'reference': {
                'urls': [{
                    'value': 'https://cds.cern.ch/record/'
                }],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_url_rejects_empty_ads_id():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_url('http://adsabs.harvard.edu/abs/')

    expected = [
        {
            'reference': {
                'urls': [{
                    'value': 'http://adsabs.harvard.edu/abs/'
                }],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_add_report_number_rejects_duplicates():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()

    builder.add_report_number('ATL-TDR-19')
    builder.add_report_number('ATL-TDR-19')

    expected = [
        {
            'reference': {
                'report_numbers': [
                    'ATL-TDR-19',
                ],
            },
        },
    ]
    result = [builder.obj]

    assert validate(result, subschema) is None
    assert expected == result


def test_pop_additional_pubnotes_no_misc():
    builder = ReferenceBuilder()

    expected = []
    result = list(builder.pop_additional_pubnotes())

    assert expected == result


def test_pop_additional_pubnotes_no_additional_pubnote():
    builder = ReferenceBuilder()
    builder.add_misc("No additional pubnote")

    expected = []
    result = list(builder.pop_additional_pubnotes())

    assert expected == result


def test_pop_additional_pubnotes_single_pubnote():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    builder.add_misc("Additional pubnote: J.Testing,42,R477")

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Testing',
                    'journal_volume': '42',
                    'page_start': 'R477',
                    'artid': 'R477'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
        },
    ]
    result = list(builder.pop_additional_pubnotes())

    assert validate(result, subschema) is None
    assert expected == result
    assert 'misc' not in builder.obj['reference']


def test_pop_additional_pubnotes_several_pubnotes():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    builder.add_misc("Additional pubnote: J.Improbable Testing,453,42-47 / some other stuff")
    builder.add_misc("Additional pubnote: J.Testing,42,R477")

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Improbable Testing',
                    'journal_volume': '453',
                    'page_start': '42',
                    'page_end': '47'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
        },
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Testing',
                    'journal_volume': '42',
                    'page_start': 'R477',
                    'artid': 'R477'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
        },
    ]
    result = list(builder.pop_additional_pubnotes())

    assert validate(result, subschema) is None
    assert expected == result
    assert builder.obj['reference']['misc'] == ['some other stuff']


def test_pop_additional_pubnotes_several_pubnotes_without_remaining_misc():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    builder.add_misc("Additional pubnote: J.Improbable Testing,453,42-47")
    builder.add_misc("Additional pubnote: J.Testing,42,R477")

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Improbable Testing',
                    'journal_volume': '453',
                    'page_start': '42',
                    'page_end': '47'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
        },
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Testing',
                    'journal_volume': '42',
                    'page_start': 'R477',
                    'artid': 'R477'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
        },
    ]
    result = list(builder.pop_additional_pubnotes())

    assert validate(result, subschema) is None
    assert expected == result
    assert 'misc' not in builder.obj['reference']


def test_pop_additional_pubnotes_includes_label():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    builder.add_misc("Additional pubnote: J.Testing,42,R477")
    builder.set_label('Hello')

    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Testing',
                    'journal_volume': '42',
                    'page_start': 'R477',
                    'artid': 'R477'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
                'label': 'Hello',
            },
        },
    ]
    result = list(builder.pop_additional_pubnotes())

    assert validate(result, subschema) is None
    assert expected == result
    assert 'misc' not in builder.obj['reference']
    assert builder.obj['reference']['label'] == 'Hello'


def test_pop_additional_pubnotes_includes_raw_ref():
    schema = load_schema('hep')
    subschema = schema['properties']['references']

    builder = ReferenceBuilder()
    builder.add_misc("Additional pubnote: J.Testing,42,R477")
    builder.add_raw_reference("A raw ref")

    expected_raw_refs = [
        {
            'schema': 'text',
            'value': 'A raw ref'
        },
    ]
    expected = [
        {
            'reference': {
                'publication_info': {
                    'journal_title': 'J.Testing',
                    'journal_volume': '42',
                    'page_start': 'R477',
                    'artid': 'R477'
                },
                'misc': [
                    'Additional pubnote split from previous reference',
                ],
            },
            'raw_refs': expected_raw_refs,
        },
    ]
    result = list(builder.pop_additional_pubnotes())

    assert validate(result, subschema) is None
    assert expected == result
    assert 'misc' not in builder.obj['reference']
    assert builder.obj['raw_refs'] == expected_raw_refs


def test_reference_builder_skip_authors_without_full_names():
    rb = ReferenceBuilder()
    rb.add_refextract_authors_str("Author 1,   ,Author 2")
    rb.add_raw_reference("Author 1, , Author 2, Some Title"),
    rb.add_title("Some title")

    expected_authors = [{'full_name': '1, Author'}, {'full_name': '2, Author'}]

    assert len(rb.obj['reference']['authors'])
    assert rb.obj['reference']['authors'] == expected_authors


def test_reference_builder_is_not_creating_author_empty_list_when_authors_missing():
    rb = ReferenceBuilder()
    rb.add_author(" ")
    rb.add_author("    ")
    assert 'reference' not in rb.obj

    rb.add_title("Title")
    rb.add_author("      ")

    assert 'authors' not in rb.obj['reference']


def test_reference_builder_is_not_adding_doi_when_already_present():
    rb = ReferenceBuilder()
    rb.add_url('https://doi.org/10.1088/1009-0630/7/4/022')
    rb.add_uid('10.1088/1009-0630/7/4/022')

    assert rb.obj['reference']['dois'] == ['10.1088/1009-0630/7/4/022']


def test_reference_builder_adds_arxiv_in_doi_format_pre_2007():
    rb = ReferenceBuilder()
    rb.add_uid('10.48550/arXiv.hep-th/050502')

    expected = {
        'reference': {
            'arxiv_eprint': 'hep-th/050502'
        },
    }

    assert rb.obj == expected


def test_reference_builder_adds_arxiv_in_doi_format_post_2007():
    rb = ReferenceBuilder()
    rb.add_uid('10.48550/arXiv.2212.07286')

    expected = {
        'reference': {
            'arxiv_eprint': '2212.07286'
        },
    }

    assert rb.obj == expected


def test_reference_builder_adds_arxiv_url_pre_2007():
    rb = ReferenceBuilder()
    rb.add_uid('https://arXiv.org/abs/hep-th/050502')

    expected = {
        'reference': {
            'arxiv_eprint': 'hep-th/050502'
        },
    }

    assert rb.obj == expected


def test_reference_builder_adds_arxiv_url_pre_2007():
    rb = ReferenceBuilder()
    rb.add_uid('https://arXiv.org/pdf/2212.07286')

    expected = {
        'reference': {
            'arxiv_eprint': '2212.07286'
        },
    }

    assert rb.obj == expected
