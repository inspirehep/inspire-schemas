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

"""Module to namespace all the exceptions."""


class InspireSchemasException(Exception):
    """Base class for all the exceptions in this package."""

    pass


class SchemaNotFound(InspireSchemasException):
    """Exception raised on missing schema."""

    def __init__(self, schema):
        """Exception raised on missing schema.

        :param schema: the schema that was requested.
        """
        message = 'Unable to find schema "{}"'.format(
            schema)
        super(SchemaNotFound, self).__init__(message)


class SchemaKeyNotFound(InspireSchemasException):
    """Exception raised on missing schema key."""

    def __init__(self, data):
        """Exception raised on missing schema key.

        :param data: data dict that was checked.
        """
        message = 'Unable to find "$schema" key in "{}".'.format(data)
        super(SchemaKeyNotFound, self).__init__(message)


class SchemaUIDConflict(InspireSchemasException):
    """Exception raised when a UID is not matching provided schema."""

    def __init__(self, schema, uid):
        """Exception raised when a UID is not matching provided schema.

        Args:
            schema (string): given schema
            uid (string): UID which conflicts the schema
        """
        message = 'UID "{}" is not of the schema "{}".'.format(uid, schema)
        super(SchemaUIDConflict, self).__init__(message)


class UnknownUIDSchema(InspireSchemasException):
    """Exception raised when a schema of a UID is unknown."""

    def __init__(self, uid):
        """Exception raised when a schema of a UID is unknown.

        Args:
            uid (string): given UID
        """
        message = 'Schema of UID "{}" is unrecognized.'.format(uid)
        super(UnknownUIDSchema, self).__init__(message)
