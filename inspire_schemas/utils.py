# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2016, 2017 CERN.
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

"""Public api for methods and functions to handle/verify the jsonschemas."""

import copy
import json
import os
import re

import six
from idutils import is_orcid
from inspire_utils.date import PartialDate
from jsonschema import validate as jsonschema_validate
from jsonschema import RefResolver, draft4_format_checker
from pkg_resources import resource_filename
from unidecode import unidecode

from six.moves.urllib.parse import urlsplit

from .errors import SchemaKeyNotFound, SchemaNotFound

_schema_root_path = os.path.abspath(resource_filename(__name__, 'records'))
_resolved_schema_root_path = os.path.abspath(resource_filename(__name__, 'resolved_records'))

_RE_2_CHARS = re.compile(r'[a-z].*[a-z]', re.IGNORECASE)
_RE_CHAR = re.compile(r'[a-z]', re.IGNORECASE)
_RE_AND = re.compile(r'\band\b', re.IGNORECASE)
_RE_COLLABORATION_LEADING = re.compile(
    r'^\s*(\b(for|on behalf of|representing)\b)?\s*(\bthe\b)?', re.IGNORECASE
)
_RE_COLLABORATION_TRAILING = re.compile(
    r'\bcollaborations?\s*$', re.IGNORECASE
)
_RE_LICENSE_URL = re.compile(
    r'^/licenses/(?P<sublicense>[-\w]*)(?:/(?P<version>[\.\d]*))?'
)
_RE_VOLUME_STARTS_WITH_A_LETTER = re.compile(
    r'^(?P<letter>[A-Z])(?P<volume>\d+)', re.IGNORECASE
)
_RE_VOLUME_ENDS_WITH_A_LETTER = re.compile(
    r'(?P<volume>\d+)(?P<letter>[A-Z])$', re.IGNORECASE
)
_RE_TITLE_ENDS_WITH_A_LETTER = re.compile(
    r'(?P<title>.+(\.| ))(?P<letter>[A-Z])$', re.IGNORECASE
)


# list produced from https://arxiv.org/archive/
_NEW_CATEGORIES = {
    'acc-phys': 'physics.acc-ph',
    'adap-org': 'nlin.AO',
    'alg-geom': 'math.AG',
    'ao-sci': 'physics.ao-ph',
    'atom-ph': 'physics.atom-ph',
    'bayes-an': 'physics.data-an',
    'chao-dyn': 'nlin.CD',
    'chem-ph': 'physics.chem-ph',
    'cmp-lg': 'cs.CL',
    'comp-gas': 'nlin.CG',
    'dg-ga': 'math.DG',
    'funct-an': 'math.FA',
    'mtrl-th': 'cont-mat.mtrl-sci',
    'patt-sol': 'nlin.PS',
    'plasm-ph': 'physics.plasm-ph',
    'q-alg': 'math.QA',
    'solv-int': 'nlin.SI',
    'supr-con': 'cond-mat.supr-con',
}

ARXIV_TO_INSPIRE_CATEGORY_MAPPING = {
    'astro-ph': 'Astrophysics',
    'astro-ph.CO': 'Astrophysics',
    'astro-ph.EP': 'Astrophysics',
    'astro-ph.GA': 'Astrophysics',
    'astro-ph.HE': 'Astrophysics',
    'astro-ph.IM': 'Instrumentation',
    'astro-ph.SR': 'Astrophysics',
    'cond-mat': 'General Physics',
    'cond-mat.dis-nn': 'General Physics',
    'cond-mat.mes-hall': 'General Physics',
    'cond-mat.mtrl-sci': 'General Physics',
    'cond-mat.other': 'General Physics',
    'cond-mat.quant-gas': 'General Physics',
    'cond-mat.soft': 'General Physics',
    'cond-mat.stat-mech': 'General Physics',
    'cond-mat.str-el': 'General Physics',
    'cond-mat.supr-con': 'General Physics',
    'cs': 'Computing',
    'cs.AI': 'Computing',
    'cs.AR': 'Computing',
    'cs.CC': 'Computing',
    'cs.CE': 'Computing',
    'cs.CG': 'Computing',
    'cs.CL': 'Computing',
    'cs.CR': 'Computing',
    'cs.CV': 'Computing',
    'cs.CY': 'Computing',
    'cs.DB': 'Computing',
    'cs.DC': 'Computing',
    'cs.DL': 'Computing',
    'cs.DM': 'Computing',
    'cs.DS': 'Computing',
    'cs.ET': 'Computing',
    'cs.FL': 'Computing',
    'cs.GL': 'Computing',
    'cs.GR': 'Computing',
    'cs.GT': 'Computing',
    'cs.HC': 'Computing',
    'cs.IR': 'Computing',
    'cs.IT': 'Computing',
    'cs.LG': 'Computing',
    'cs.LO': 'Computing',
    'cs.MA': 'Computing',
    'cs.MM': 'Computing',
    'cs.MS': 'Computing',
    'cs.NA': 'Computing',
    'cs.NE': 'Computing',
    'cs.NI': 'Computing',
    'cs.OH': 'Computing',
    'cs.OS': 'Computing',
    'cs.PF': 'Computing',
    'cs.PL': 'Computing',
    'cs.RO': 'Computing',
    'cs.SC': 'Computing',
    'cs.SD': 'Computing',
    'cs.SE': 'Computing',
    'cs.SI': 'Computing',
    'cs.SY': 'Computing',
    'gr-qc': 'Gravitation and Cosmology',
    'hep-ex': 'Experiment-HEP',
    'hep-lat': 'Lattice',
    'hep-ph': 'Phenomenology-HEP',
    'hep-th': 'Theory-HEP',
    'math': 'Math and Math Physics',
    'math-ph': 'Math and Math Physics',
    'math.AC': 'Math and Math Physics',
    'math.AG': 'Math and Math Physics',
    'math.AP': 'Math and Math Physics',
    'math.AT': 'Math and Math Physics',
    'math.CA': 'Math and Math Physics',
    'math.CO': 'Math and Math Physics',
    'math.CT': 'Math and Math Physics',
    'math.CV': 'Math and Math Physics',
    'math.DG': 'Math and Math Physics',
    'math.DS': 'Math and Math Physics',
    'math.FA': 'Math and Math Physics',
    'math.GM': 'Math and Math Physics',
    'math.GN': 'Math and Math Physics',
    'math.GR': 'Math and Math Physics',
    'math.GT': 'Math and Math Physics',
    'math.HO': 'Math and Math Physics',
    'math.IT': 'Math and Math Physics',
    'math.KT': 'Math and Math Physics',
    'math.LO': 'Math and Math Physics',
    'math.MG': 'Math and Math Physics',
    'math.MP': 'Math and Math Physics',
    'math.NA': 'Math and Math Physics',
    'math.NT': 'Math and Math Physics',
    'math.OA': 'Math and Math Physics',
    'math.OC': 'Math and Math Physics',
    'math.PR': 'Math and Math Physics',
    'math.QA': 'Math and Math Physics',
    'math.RA': 'Math and Math Physics',
    'math.RT': 'Math and Math Physics',
    'math.SG': 'Math and Math Physics',
    'math.SP': 'Math and Math Physics',
    'math.ST': 'Math and Math Physics',
    'nlin': 'General Physics',
    'nlin.AO': 'General Physics',
    'nlin.CD': 'General Physics',
    'nlin.CG': 'General Physics',
    'nlin.PS': 'Math and Math Physics',
    'nlin.SI': 'Math and Math Physics',
    'nucl-ex': 'Experiment-Nucl',
    'nucl-th': 'Theory-Nucl',
    'physics': 'General Physics',
    'physics.acc-ph': 'Accelerators',
    'physics.ao-ph': 'General Physics',
    'physics.atm-clus': 'General Physics',
    'physics.atom-ph': 'General Physics',
    'physics.bio-ph': 'Other',
    'physics.chem-ph': 'Other',
    'physics.class-ph': 'General Physics',
    'physics.comp-ph': 'Computing',
    'physics.data-an': 'Data Analysis and Statistics',
    'physics.ed-ph': 'Other',
    'physics.flu-dyn': 'General Physics',
    'physics.gen-ph': 'General Physics',
    'physics.geo-ph': 'General Physics',
    'physics.hist-ph': 'Other',
    'physics.ins-det': 'Instrumentation',
    'physics.med-ph': 'Other',
    'physics.optics': 'General Physics',
    'physics.plasm-ph': 'General Physics',
    'physics.pop-ph': 'Other',
    'physics.soc-ph': 'Other',
    'physics.space-ph': 'Astrophysics',
    'quant-ph': 'General Physics',
}

_JOURNALS_ALREADY_ENDING_WITH_A_LETTER = {
    'Acta Cryst.A',
    'Acta Cryst.B',
    'Acta Cryst.D',
    'Acta Cryst.F',
    'Adv.Phys.X',
    'Annales Soc.Sci.Bruxelles A',
    'Appl.Catal.A',
    'Appl.Sci.Res.,Sect.A',
    'Bull.Okayama Univ.Sci.A',
    'Can.J.Res.A',
    'Cesk.Cas.Fys.A',
    'Chin.Ann.Math.B',
    'Colloids Surf.A',
    'Commun.Dublin Inst.Ser.A',
    'Concepts Magn.Reson.Part A',
    'Concepts Magn.Reson.Part B',
    'Global J.Sci.Front.Res.A',
    'ITB J.Sci.A',
    'Indian J.Phys.A',
    'Indian J.Phys.B',
    'Indian J.Statist.A',
    'Iran.J.Sci.Technol.A',
    'J.Chromatogr.A',
    'J.Mol.Catal.A',
    'J.Opt.A',
    'J.Opt.B',
    'J.Polymer Sci.B',
    'J.Res.Natl.Bur.Stand.A',
    'J.Res.Natl.Bur.Stand.B',
    'Kumamoto J.Sci.Ser.A',
    'NATO Sci.Peace Secur.B',
    'NATO Sci.Ser.B',
    'NATO Sci.Ser.C',
    'NATO Sci.Ser.F',
    'Nucl.Data Sheets A',
    'Nucl.Data Sheets B',
    'Nucl.Sci.Appl.A',
    'Phil.Trans.Roy.Soc.Lond.B',
    'Polymer Sci.B',
    'Proc.Rom.Acad.A',
    'Rev.Univ.Nac.Tucuman, Ser.A',
    'Sci.Rep.Nat Tsing Hua Univ.Ser.A',
    'Spectrochim.Acta A',
    'Tellus A',
    'Trans.Int.Astron.Union A',
}

_JOURNALS_THAT_NEED_A_HIDDEN_PUBNOTE = {
    'Phys.Lett.B': set(str(el) for el in range(24, 171)),
}

_JOURNALS_RENAMED_OLD_TO_NEW = {
    'Ann.Inst.H.Poincare Anal.Non Lineaire': 'Ann.Inst.H.Poincare C Anal.Non Lineaire',
    'Annales Soc.Sci.Brux.Ser.I Sci.Math.Astron.Phys.': 'Annales Soc.Sci.Bruxelles.I',
    'Annales Soc.Sci.Bruxelles Ser.B Sci.Phys.Nat.': 'Annales Soc.Sci.Bruxelles B',
    'Diss.Abstr.Int.': 'Diss.Abstr.Int.B',
    'J.Comb.Theory Ser.': 'J.Comb.Theor.A',
    'J.Vac.Sci.Technol.A Vac.Surf.Films': 'J.Vac.Sci.Technol.A',
    'J.Vac.Sci.Technol.B Microelectron.Nanometer Struct.': 'J.Vac.Sci.Technol.B',
    'Nucl.Phys.Proc.Suppl.': 'Nucl.Phys.B Proc.Suppl.',
    'Proc.Roy.Irish Acad.(Sect.A)': 'Proc.Roy.Irish Acad.A',
    'Proc.Roy.Soc.Lond.': 'Proc.Roy.Soc.Lond.A',
    'Univ.Politech.Bucharest Sci.Bull.': 'Univ.Politech.Bucharest Sci.Bull.A',
}
_JOURNALS_RENAMED_NEW_TO_OLD = {v: k for (k, v) in six.iteritems(_JOURNALS_RENAMED_OLD_TO_NEW)}

_JOURNALS_WITH_YEAR_ADDED_TO_VOLUME = {
    'JHEP',
    'JCAP',
}


def normalize_arxiv_category(category):
    """Normalize arXiv category to be schema compliant.

    This properly capitalizes the category and replaces the dash by a dot if
    needed. If the category is obsolete, it also gets converted it to its
    current equivalent.

    Example:
        >>> from inspire_schemas.utils import normalize_arxiv_category
        >>> normalize_arxiv_category('funct-an')
        u'math.FA'

    """
    category = _NEW_CATEGORIES.get(category.lower(), category)
    for valid_category in valid_arxiv_categories():
        if (category.lower() == valid_category.lower() or
                category.lower().replace('-', '.') == valid_category.lower()):
            return valid_category
    return category  # XXX: will fail validation and be logged


def valid_arxiv_categories():
    """List of all arXiv categories that ever existed.

    Example:
        >>> from inspire_schemas.utils import valid_arxiv_categories
        >>> 'funct-an' in valid_arxiv_categories()
        True

    """
    schema = load_schema('elements/arxiv_categories')
    categories = schema['enum']
    categories.extend(_NEW_CATEGORIES.keys())

    return categories


def classify_field(value):
    """Normalize ``value`` to an Inspire category.

    Args:
        value(str): an Inspire category to properly case, or an arXiv category
            to translate to the corresponding Inspire category.

    Returns:
        str: ``None`` if ``value`` is not a non-empty string,
            otherwise the corresponding Inspire category.

    """
    if not (isinstance(value, six.string_types) and value):
        return

    schema = load_schema('elements/inspire_field')
    inspire_categories = schema['properties']['term']['enum']

    for inspire_category in inspire_categories:
        if value.upper() == inspire_category.upper():
            return inspire_category

    category = normalize_arxiv_category(value)
    return ARXIV_TO_INSPIRE_CATEGORY_MAPPING.get(category, 'Other')


def split_page_artid(page_artid):
    """Split page_artid into page_start/end and artid."""
    page_start = None
    page_end = None
    artid = None

    if not page_artid:
        return None, None, None

    # normalize unicode dashes
    page_artid = unidecode(six.text_type(page_artid))

    if '-' in page_artid:
        # if it has a dash it's a page range
        page_range = page_artid.replace('--', '-').split('-')
        if len(page_range) == 2:
            page_start, page_end = page_range
        else:
            artid = page_artid
    elif _RE_2_CHARS.search(page_artid):
        # if it has 2 or more letters it's an article ID
        artid = page_artid
    elif len(_RE_CHAR.sub('', page_artid)) >= 5:
        # if there are more than 5 digits it's an article ID
        artid = page_artid
    else:
        if artid is None:
            artid = page_artid
        if page_start is None:
            page_start = page_artid

    return page_start, page_end, artid


def split_pubnote(pubnote_str):
    """Split pubnote into journal information."""
    pubnote = {}
    parts = pubnote_str.split(',')

    if len(parts) > 2:
        pubnote['journal_title'] = parts[0]
        pubnote['journal_volume'] = parts[1]
        pubnote['page_start'], pubnote['page_end'], pubnote['artid'] = split_page_artid(parts[2])

    return {key: val for (key, val) in six.iteritems(pubnote) if val is not None}


def build_pubnote(title, volume, page_start, page_end, artid):
    """Build pubnote string from parts (reverse of split_pubnote)."""
    pubnote = None
    if title and volume:
        pubnote = '{},{}'.format(title, volume)
        if page_start and page_end:
            pubnote += ',{}-{}'.format(page_start, page_end)
        elif page_start:
            pubnote += ',{}'.format(page_start)
        if artid and artid != page_start:
            pubnote += ',{}'.format(artid)

    return pubnote


class LocalRefResolver(RefResolver):
    """Simple resolver to handle non-uri relative paths."""

    def resolve_remote(self, uri):
        """Resolve a uri or relative path to a schema."""
        try:
            return super(LocalRefResolver, self).resolve_remote(uri)
        except ValueError:
            return super(LocalRefResolver, self).resolve_remote(
                'file://' + get_schema_path(uri.rsplit('.json', 1)[0])
            )


def get_schema_path(schema, resolved=False):
    """Retrieve the installed path for the given schema.

    Args:
        schema(str): relative or absolute url of the schema to validate, for
            example, 'records/authors.json' or 'jobs.json', or just the name of the
            schema, like 'jobs'.
        resolved(bool): if True, the returned path points to a fully resolved
            schema, that is to the schema with all `$ref` replaced by their
            targets.

    Returns:
        str: path to the given schema name.

    Raises:
        SchemaNotFound: if no schema could be found.
    """
    def _strip_first_path_elem(path):
        """Pass doctests.

        Strip the first element of the given path, returning an empty string if
        there are no more elements. For example, 'something/other' will end up
        as 'other', but  passing then 'other' will return ''
        """
        stripped_path = path.split(os.path.sep, 1)[1:]
        return ''.join(stripped_path)

    def _schema_to_normalized_path(schema):
        """Pass doctests.

        Extracts the path from the url, makes sure to get rid of any '..' in
        the path and adds the json extension if not there.
        """
        path = os.path.normpath(os.path.sep + urlsplit(schema).path)
        if path.startswith(os.path.sep):
            path = path[1:]

        if not path.endswith('.json'):
            path += '.json'

        return path

    path = _schema_to_normalized_path(schema)
    while path:
        if resolved:
            schema_path = os.path.abspath(os.path.join(_resolved_schema_root_path, path))
        else:
            schema_path = os.path.abspath(os.path.join(_schema_root_path, path))
        if os.path.exists(schema_path):
            return os.path.abspath(schema_path)

        path = _strip_first_path_elem(path)

    raise SchemaNotFound(schema=schema)


def load_schema(schema_name, resolved=False):
    """Load the given schema from wherever it's installed.

    Args:
        schema_name(str): Name of the schema to load, for example 'authors'.
        resolved(bool): If True will return the resolved schema, that is with
            all the $refs replaced by their targets.

    Returns:
        dict: the schema with the given name.
    """
    schema_data = ''
    with open(get_schema_path(schema_name, resolved)) as schema_fd:
        schema_data = json.loads(schema_fd.read())

    if '$schema' not in schema_data:
        schema_data = {'$schema': schema_data}

    return schema_data


inspire_format_checker = draft4_format_checker
inspire_format_checker.checks('date', raises=ValueError)(PartialDate.loads)
inspire_format_checker.checks('orcid')(is_orcid)


def validate(data, schema=None):
    """Validate the given dictionary against the given schema.

    Args:
        data (dict): record to validate.
        schema (Union[dict, str]): schema to validate against. If it is a
            string, it is intepreted as the name of the schema to load (e.g.
            ``authors`` or ``jobs``). If it is ``None``, the schema is taken
            from ``data['$schema']``. If it is a dictionary, it is used
            directly.

    Raises:
        SchemaNotFound: if the given schema was not found.
        SchemaKeyNotFound: if ``schema`` is ``None`` and no ``$schema`` key was
            found in ``data``.
        jsonschema.SchemaError: if the schema is invalid.
        jsonschema.ValidationError: if the data is invalid.
    """
    if schema is None:
        if '$schema' not in data:
            raise SchemaKeyNotFound(data=data)
        schema = data['$schema']

    if isinstance(schema, six.string_types):
        schema = load_schema(schema_name=schema)

    return jsonschema_validate(
        instance=data,
        schema=schema,
        resolver=LocalRefResolver.from_schema(schema),
        format_checker=inspire_format_checker,
    )


def normalize_collaboration(collaboration):
    """Normalize collaboration string.

    Args:
        collaboration: a string containing collaboration(s) or None

    Returns:
        list: List of extracted and normalized collaborations

    Examples:
        >>> from inspire_schemas.utils import normalize_collaboration
        >>> normalize_collaboration('for the CMS and ATLAS Collaborations')
        ['CMS', 'ATLAS']
    """
    if not collaboration:
        return []

    collaborations = _RE_AND.split(collaboration)
    collaborations = (_RE_COLLABORATION_LEADING.sub('', collab)
                      for collab in collaborations)
    collaborations = (_RE_COLLABORATION_TRAILING.sub('', collab)
                      for collab in collaborations)

    return [collab.strip() for collab in collaborations]


def get_license_from_url(url):
    """Get the license abbreviation from an URL.

    Args:
        url(str): canonical url of the license.

    Returns:
        str: the corresponding license abbreviation.

    Raises:
        ValueError: when the url is not recognized
    """
    if not url:
        return

    split_url = urlsplit(url, scheme='http')

    if split_url.netloc.lower() == 'creativecommons.org':
        license = ['CC']
        match = _RE_LICENSE_URL.match(split_url.path)
        license.extend(part.upper() for part in match.groups() if part)
    elif split_url.netloc == 'arxiv.org':
        license = ['arXiv']
        match = _RE_LICENSE_URL.match(split_url.path)
        license.extend(part for part in match.groups() if part)
    else:
        raise ValueError('Unknown license URL')

    return u' '.join(license)


def convert_old_publication_info_to_new(publication_infos):
    """Convert a ``publication_info`` value from the old format to the new.

    On Legacy different series of the same journal were modeled by adding the
    letter part of the name to the journal volume. For example, a paper published
    in Physical Review D contained::

        {
            'publication_info': [
                {
                    'journal_title': 'Phys.Rev.',
                    'journal_volume': 'D43',
                },
            ],
        }

    On Labs we instead represent each series with a different journal record. As
    a consequence, the above example becomes::

        {
            'publication_info': [
                {
                    'journal_title': 'Phys.Rev.D',
                    'journal_volume': '43',
                },
            ],
        }

    This function handles this translation from the old format to the new. Please
    also see the tests for various edge cases that this function also handles.

    Args:
        publication_infos: a ``publication_info`` in the old format.

    Returns:
        list(dict): a ``publication_info`` in the new format.

    """
    result = []
    hidden_publication_infos = []

    for publication_info in publication_infos:
        _publication_info = copy.deepcopy(publication_info)
        journal_title = _publication_info.get('journal_title')

        try:
            journal_title = _JOURNALS_RENAMED_OLD_TO_NEW[journal_title]
            _publication_info['journal_title'] = journal_title
            result.append(_publication_info)
            continue
        except KeyError:
            pass

        journal_volume = _publication_info.get('journal_volume')

        if journal_title in _JOURNALS_WITH_YEAR_ADDED_TO_VOLUME and journal_volume and len(journal_volume) == 4:
            _publication_info['journal_volume'] = journal_volume[2:]
            result.append(_publication_info)
            continue

        if journal_title and journal_volume:
            volume_starts_with_a_letter = _RE_VOLUME_STARTS_WITH_A_LETTER.match(journal_volume)
            volume_ends_with_a_letter = _RE_VOLUME_ENDS_WITH_A_LETTER.match(journal_volume)
            match = volume_starts_with_a_letter or volume_ends_with_a_letter
            if match:
                _publication_info.pop('journal_record', None)
                _publication_info['journal_title'] = ''.join([
                    journal_title,
                    '' if journal_title.endswith('.') else ' ',
                    match.group('letter'),
                ])
                _publication_info['journal_volume'] = match.group('volume')

        hidden = _publication_info.pop('hidden', None)
        if hidden:
            hidden_publication_infos.append(_publication_info)
        else:
            result.append(_publication_info)

    for publication_info in hidden_publication_infos:
        if publication_info not in result:
            publication_info['hidden'] = True
            result.append(publication_info)

    return result


def convert_new_publication_info_to_old(publication_infos):
    """Convert back a ``publication_info`` value from the new format to the old.

    Does the inverse transformation of :func:`convert_old_publication_info_to_new`,
    to be used whenever we are sending back records from Labs to Legacy.

    Args:
        publication_infos: a ``publication_info`` in the new format.

    Returns:
        list(dict): a ``publication_info`` in the old format.

    """
    def _needs_a_hidden_pubnote(journal_title, journal_volume):
        return (
            journal_title in _JOURNALS_THAT_NEED_A_HIDDEN_PUBNOTE and
            journal_volume in _JOURNALS_THAT_NEED_A_HIDDEN_PUBNOTE[journal_title]
        )

    result = []

    for publication_info in publication_infos:
        _publication_info = copy.deepcopy(publication_info)
        journal_title = _publication_info.get('journal_title')

        try:
            journal_title = _JOURNALS_RENAMED_NEW_TO_OLD[journal_title]
            _publication_info['journal_title'] = journal_title
            result.append(_publication_info)
            continue
        except KeyError:
            pass

        journal_volume = _publication_info.get('journal_volume')
        year = _publication_info.get('year')

        if (journal_title in _JOURNALS_WITH_YEAR_ADDED_TO_VOLUME and year and
                journal_volume and len(journal_volume) == 2):
            two_digit_year = str(year)[2:]
            _publication_info['journal_volume'] = ''.join([two_digit_year, journal_volume])
            result.append(_publication_info)
            continue

        if journal_title and journal_volume:
            match = _RE_TITLE_ENDS_WITH_A_LETTER.match(journal_title)
            if match and _needs_a_hidden_pubnote(journal_title, journal_volume):
                _publication_info['journal_title'] = match.group('title')
                _publication_info['journal_volume'] = journal_volume + match.group('letter')
                result.append(_publication_info)
                _publication_info = copy.deepcopy(publication_info)
                _publication_info['hidden'] = True
                _publication_info['journal_title'] = match.group('title')
                _publication_info['journal_volume'] = match.group('letter') + journal_volume
            elif match and journal_title not in _JOURNALS_ALREADY_ENDING_WITH_A_LETTER:
                _publication_info['journal_title'] = match.group('title')
                _publication_info['journal_volume'] = match.group('letter') + journal_volume

        result.append(_publication_info)

    return result
