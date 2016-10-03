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
from jsonschema import validate as jsonschema_validate

from .errors import SchemaKeyNotFound
from .utils import LocalRefResolver, load_schema


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
    )
