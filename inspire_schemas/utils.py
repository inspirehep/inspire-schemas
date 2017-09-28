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
import datetime
import itertools
import json
import os
import re

import six
from dateutil.parser import parse as parse_date
from inspire_utils.helpers import maybe_int
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


def format_date(year, month=None, day=None):
    """Format a (potentially incomplete) date given its numeric components.

    If a component is a numeric `str` or an `int` it will be used, otherwise it
    will be ignored.

    If parsing of textual data is needed, :func:`normalize_date` should be used
    instead.

    Returns:
        str: a formatted date, in the form YYYY-MM-DD, YYYY-MM or YYYY
            (depending on the information present in the date).

    Raises:
        ValueError: when year does not contain valid data.

    Examples:

        >>> from inspire_schemas.utils import format_date
        >>> format_date(year=1686, month=6, day=30)
        '1686-06-30'
        >>> format_date(year='1686', month='June', day='30')
        '1686'

        The following snippet can be used to convert legacy conference dates:

        >>> from inspire_schemas.utils import format_date
        >>> format_date(*'2014-05-00'.split('-'))
        '2014-05'
    """
    # XXX: 0 is not a valid year/month/day
    non_empty = itertools.takewhile(
        bool, (maybe_int(part) for part in (year, month, day))
    )
    # XXX: this only handles dates after 1000, which should be sufficient
    formatted = ('{:02d}'.format(part) for part in non_empty)
    date = '-'.join(formatted)
    if not date:
        raise ValueError('impossible to format a date with no valid year')

    return date


def normalize_date(date):
    """Normalize a date.

    This attempts to normalize the input date, given in an arbitrary format, to
    the format used internally.

    Args:
        date(str): date to normalize

    Returns:
        str: normalized date, in the form ``YYYY-MM-DD``, ``YYYY-MM`` or
            ``YYYY`` (depending on the information present in the date).

    Raises:
        ValueError: when the date cannot be parsed or no year is present in
            it.

    Examples:
        >>> from inspire_schemas.utils import normalize_date
        >>> normalize_date('30 Jun 1686')
        '1686-06-30'
    """
    # In order to detect partial dates, parse twice with different defaults
    # and compare the results.
    default_date1 = datetime.datetime(1, 1, 1)
    default_date2 = datetime.datetime(2, 2, 2)

    parsed_date1 = parse_date(date, default=default_date1)
    parsed_date2 = parse_date(date, default=default_date2)

    has_year = parsed_date1.year == parsed_date2.year
    has_month = parsed_date1.month == parsed_date2.month
    has_day = parsed_date1.day == parsed_date2.day

    if has_year:
        year = parsed_date1.year
    else:
        raise ValueError('date does not contain a year')
    month = parsed_date1.month if has_month else None
    day = parsed_date1.day if has_day else None

    return format_date(year, month, day)
