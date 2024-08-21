#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of INSPIRE-SCHEMAS.
# Copyright (C) 2017 CERN.
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

'''
Normalize YAML files to use non-flow style and block scalars in
``description``.
'''

from __future__ import print_function

import collections
import fnmatch
import os
import warnings

import yaml
from yaml.representer import SafeRepresenter

# -----------------------------------------------
# Configuration

DUMPER_OPTIONS = {
    'default_flow_style': False,
    'allow_unicode': True,
    'indent': 4,
    'width': 80,
}

SCALAR_STYLE = '|'

# -----------------------------------------------


class DescriptionContent(str):
    '''Class to tag the value of ``description``s'''

    pass


# Taken from http://stackoverflow.com/questions/6432605/any-yaml-libraries-in-python-that-support-dumping-of-long-strings-as-block-liter
def change_style(style, representer):
    def new_representer(dumper, data):
        scalar = representer(dumper, data)
        scalar.style = style
        return scalar

    return new_representer


represent_description_content = change_style(
    SCALAR_STYLE, SafeRepresenter.represent_str
)
yaml.add_representer(DescriptionContent, represent_description_content)


def process_tree(value, key=None, parent_key=None):
    def _process_leaf(value, key=None, parent_key=None):
        if key == 'description' and parent_key != 'properties':
            return DescriptionContent(value.strip())

        return value

    def _enforce_strict_types(dictionary):
        if dictionary.get('type') == 'object':
            dictionary.setdefault('additionalProperties', False)
        elif dictionary.get('type') == 'string':
            dictionary.setdefault('minLength', 1)
        elif dictionary.get('type') == 'array':
            dictionary.setdefault('uniqueItems', True)
            dictionary.setdefault('minItems', 1)

        return dictionary

    def _ensure_values_have_types(properties, parent_key):
        for key, val in properties.items():
            if not val.get('type') and not val.get('$ref'):
                warnings.warn(
                    u'"{}" field of "{}" does not have a type'.format(key, parent_key),
                    stacklevel=1,
                )

    def _is_leaf(value):
        return not isinstance(value, collections.Container) or isinstance(value, str)

    if _is_leaf(value):
        return _process_leaf(value, key, parent_key)

    elif isinstance(value, list):
        return [process_tree(v) for v in value]

    elif isinstance(value, dict):
        value = _enforce_strict_types(value)
        if key == 'properties':
            _ensure_values_have_types(value, parent_key)
        return {k: process_tree(v, k, key) for k, v in value.items()}

    else:
        raise TypeError(
            u"'{}' has unexpected type: {}".format(value, type(value).__name__)
        )


def normalize_yaml(file_name):
    print('Normalizing', file_name, '...')
    with open(file_name, 'r') as file_stream:
        schema = yaml.full_load(file_stream)

    schema = process_tree(schema)
    yaml_schema = yaml.dump(schema, **DUMPER_OPTIONS)

    with open(file_name, 'w') as file_stream:
        file_stream.write(yaml_schema)


def schema_files():
    for root, _, filenames in os.walk('inspire_schemas/records'):
        for filename in fnmatch.filter(filenames, '*.yml'):
            yield os.path.join(root, filename)


if __name__ == '__main__':
    for schema_file in schema_files():
        normalize_yaml(schema_file)
