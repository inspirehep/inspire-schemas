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

from urlparse import urlsplit

from jsonschema import RefResolver
from pkg_resources import resource_filename

from .errors import SchemaNotFound

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
        or 'jobs'.
    :type schema: str
    :rtype: bool
    :return: The path or the given schema name.
    :rtype: str
    """
    path = original_path = os.path.normpath(urlsplit(schema).path)
    if path.startswith(os.path.sep):
        path = path[1:]
    if not path.endswith('.json'):
        path += '.json'

    while path:
        schema_path = os.path.abspath(os.path.join(_schema_root_path, path))
        if not schema_path.startswith(_schema_root_path):
            raise SchemaNotFound(schema=schema)
        if os.path.exists(schema_path):
            return os.path.abspath(schema_path)
        # @jacquerie forgive us because we do not know what we are doing
        path = (path.split(os.path.sep, 1)[1:] or [""])[0]
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
