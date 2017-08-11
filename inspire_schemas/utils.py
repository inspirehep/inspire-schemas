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
import warnings

import six
from jsonschema import validate as jsonschema_validate
from jsonschema import RefResolver, draft4_format_checker
from nameparser import HumanName
from pkg_resources import resource_filename

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

    if '-' in page_artid:
        # if it has a dash it's a page range
        page_range = page_artid.split('-')
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
    def _is_initial(author_name):
        return len(author_name) == 1 or '.' in author_name

    def _ensure_dotted_initials(author_name):
        if _is_initial(author_name) and '.' not in author_name:
            seq = (author_name, '.')
            author_name = ''.join(seq)
        return author_name

    name = HumanName(author)

    name.first = _ensure_dotted_initials(name.first)
    name.middle = _ensure_dotted_initials(name.middle)

    if _is_initial(name.first) and _is_initial(name.middle):
        normalized_name = '{last_name}, {first_name}{middle_name}'
    else:
        normalized_name = '{last_name}, {first_name} {middle_name}'

    normalized_name = normalized_name.format(
        last_name=name.last, first_name=name.first, middle_name=name.middle
        )

    return normalized_name.rstrip()
