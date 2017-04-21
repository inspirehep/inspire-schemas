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
import json
import os
import re
import warnings

from jsonschema import validate as jsonschema_validate
from jsonschema import RefResolver, draft4_format_checker

from pkg_resources import resource_filename
from six.moves.urllib.parse import urlsplit

from .errors import SchemaKeyNotFound, SchemaNotFound


_schema_root_path = os.path.abspath(resource_filename(__name__, 'records'))


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


def validate(data, schema_name=None):
    """Validate the given dictionary against the given schema.

    :param data: Dict to validate.
    :type data: dict
    :param schema_name: String with the name of the schema to validate, for
        example, 'authors' or 'jobs'. If `None` passed it will expect for the
        data to have the schema specified in the `$ref` key.
    :type schema_name: str
    :return: None
    :raises inspire_schemas.errors.SchemaNotFound: if the given schema was not
        found.
    :raises inspire_schemas.errors.SchemaKeyNotFound: if the given schema was
        not found.
    :raises jsonschema.SchemaError: if the schema is invalid
    :raises jsonschema.ValidationError: if the data is invalid
    """
    if schema_name is None:
        if '$schema' not in data:
            raise SchemaKeyNotFound(data=data)
        schema_name = data['$schema']

    schema = load_schema(schema_name=schema_name)
    return jsonschema_validate(
        instance=data,
        schema=schema,
        resolver=LocalRefResolver.from_schema(schema),
        format_checker=draft4_format_checker,
    )


def normalize_date_iso(date):
    """Normalize date for schema (format yyyy-mm-ddT00:00:00).

    :param date: a generic date
    :type date: string with the format (yyyy-mm-dd)

    :return formatted_date: the input date in
    the format (yyyy-mm-ddT00:00:00)
    """
    warnings.warn("Don't use 'normalize_date_iso'", DeprecationWarning)

    try:
        formatted_date = datetime.datetime.\
            strptime(date, '%Y-%m-%d').isoformat()
    except (ValueError, Exception):
        formatted_date = None

    return formatted_date


def normalize_author_name_with_comma(author):
    """Normalize author name.

    :param author: author name
    :type author: string

    :return name: the name of the author normilized
    """
    def _verify_author_name_initials(author_name):
        return not bool(re.compile(r'[^A-Z. ]').search(author_name))

    name = author.split(',')
    if len(name) > 1 and _verify_author_name_initials(name[1]):
        name[1] = name[1].replace(' ', '')
    name = ', '.join(n_elem.strip() for n_elem in name)
    return name
