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

"""Public api for methods and functions to handle/verify the jsonschemas."""
import json
import os
import re

import six
from jsonschema import validate as jsonschema_validate
from jsonschema import RefResolver, draft4_format_checker
from nameparser import HumanName
from nameparser.config import Constants
from pkg_resources import resource_filename
from unidecode import unidecode

from six.moves.urllib.parse import urlsplit

from .errors import SchemaKeyNotFound, SchemaNotFound

_schema_root_path = os.path.abspath(resource_filename(__name__, 'records'))

_RE_2_CHARS = re.compile(r'[a-z].*[a-z]', re.I)

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
    'alg-geom': 'Math and Math Physics',
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
    'dg-ga': 'Math and Math Physics',
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
    'patt-sol': 'Math and Math Physics',
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
    'q-alg': 'Math and Math Physics',
    'q-bio': 'Other',
    'q-bio.BM': 'Other',
    'q-bio.CB': 'Other',
    'q-bio.GN': 'Other',
    'q-bio.MN': 'Other',
    'q-bio.NC': 'Other',
    'q-bio.OT': 'Other',
    'q-bio.PE': 'Other',
    'q-bio.QM': 'Other',
    'q-bio.SC': 'Other',
    'q-bio.TO': 'Other',
    'q-fin': 'Other',
    'q-fin.CP': 'Other',
    'q-fin.EC': 'Other',
    'q-fin.GN': 'Other',
    'q-fin.MF': 'Other',
    'q-fin.PM': 'Other',
    'q-fin.PR': 'Other',
    'q-fin.RM': 'Other',
    'q-fin.ST': 'Other',
    'q-fin.TR': 'Other',
    'quant-ph': 'General Physics',
    'solv-int': 'Math and Math Physics',
    'stat': 'Other',
    'stat.AP': 'Other',
    'stat.CO': 'Other',
    'stat.ME': 'Other',
    'stat.ML': 'Other',
    'stat.OT': 'Other',
    'stat.TH': 'Other',
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
    """Translate an arXiv category to the corresponding INSPIRE category.

    Args:
        value: arXiv category to translate

    Returns:
        str: ``None`` if ``value`` is not a string containing a valid arXiv
            category, otherwise the corresponding INSPIRE category.

    """
    if not value:
        return None
    elif not isinstance(value, six.string_types):
        return None
    else:
        casted_value = value.upper()
        for name, category in six.iteritems(ARXIV_TO_INSPIRE_CATEGORY_MAPPING):
            if name.upper() == casted_value:
                return category
            elif category.upper() == casted_value:
                return category
        return None


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
        # if it has 2 ore more letters it's an article ID
        artid = page_artid
    elif len(page_artid) >= 5:
        # it it is longer than 5 digits it's an article ID
        artid = page_artid
    else:
        if artid is None:
            artid = page_artid
        if page_start is None:
            page_start = page_artid

    return page_start, page_end, artid


def split_pubnote(pubnote_str):
    """Split pubnote into journal information."""
    title, volume, page_start, page_end, artid = (None, None, None, None, None)
    parts = pubnote_str.split(',')

    if len(parts) > 2:
        title = parts[0]
        volume = parts[1]
        page_start, page_end, artid = split_page_artid(parts[2])

    return title, volume, page_start, page_end, artid


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


def get_schema_path(schema):
    """Retrieve the installed path for the given schema.

    :param schema: String with the (relative or absolute) url of the
        schema to validate, for example, 'records/authors.json' or 'jobs.json',
        or by just the name like 'jobs'.
    :type schema: str
    :return: The path or the given schema name.
    :rtype: str
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
        schema_path = os.path.abspath(os.path.join(_schema_root_path, path))
        if os.path.exists(schema_path):
            return os.path.abspath(schema_path)

        path = _strip_first_path_elem(path)

    raise SchemaNotFound(schema=schema)


def load_schema(schema_name):
    """Load the given schema from wherever it's installed.

    :param schema_name: Name of the schema to load, for example 'authors'.
    """
    schema_data = ''
    with open(get_schema_path(schema_name)) as schema_fd:
        schema_data = json.loads(schema_fd.read())

    if '$schema' not in schema_data:
        schema_data = {'$schema': schema_data}

    return schema_data


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
        format_checker=draft4_format_checker,
    )


def normalize_author_name(author):
    """Normalize author name.

    :param author: author name
    :type author: string

    :return name: the name of the author normilized
    """
    constants = Constants()
    roman_numeral_suffixes = [u'v', u'vi', u'vii', u'viii', u'ix', u'x',
                              u'xii', u'xiii', u'xiv', u'xv']
    titles = [u'Dr', u'Prof', u'Professor', u'Sir', u'Editor', u'Ed', u'Mr',
              u'Mrs', u'Ms', u'Chair', u'Co-Chair', u'Chairs', u'co-Chairs']
    constants.titles.remove(*constants.titles).add(*titles)
    constants.suffix_not_acronyms.add(*roman_numeral_suffixes)

    def _is_initial(author_name):
        return len(author_name) == 1 or u'.' in author_name

    def _ensure_dotted_initials(author_name):
        if _is_initial(author_name)\
                and u'.' not in author_name:
            seq = (author_name, u'.')
            author_name = u''.join(seq)
        return author_name

    def _ensure_dotted_suffixes(author_suffix):
        if u'.' not in author_suffix:
            seq = (author_suffix, u'.')
            author_suffix = u''.join(seq)
        return author_suffix

    def _is_roman_numeral(suffix):
        """Controls that the userinput only contains valid roman numerals"""
        valid_roman_numerals = [u'M', u'D', u'C', u'L', u'X',
                                u'V', u'I', u'(', u')']
        return all(letters in valid_roman_numerals
                   for letters in suffix.upper())

    name = HumanName(author, constants=constants)

    name.first = _ensure_dotted_initials(name.first)
    name.middle = _ensure_dotted_initials(name.middle)

    if _is_initial(name.first) and _is_initial(name.middle):
        normalized_names = u'{first_name}{middle_name}'
    else:
        normalized_names = u'{first_name} {middle_name}'

    normalized_names = normalized_names.format(
        first_name=name.first,
        middle_name=name.middle,
    )

    if _is_roman_numeral(name.suffix):
        suffix = name.suffix.upper()
    else:
        suffix = _ensure_dotted_suffixes(name.suffix)

    final_name = u', '.join(
        part for part in (name.last, normalized_names.strip(), suffix)
        if part)

    return final_name
