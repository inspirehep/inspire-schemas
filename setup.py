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

"""INSPIRE schemas and related tools bundle."""
from __future__ import absolute_import, division, print_function

import json
import os

from setuptools import find_packages, setup

URL = 'https://github.com/inspirehep/inspire-schemas'


def _yaml2json(yaml_file, json_file):
    import yaml
    with open(yaml_file, 'rb') as yaml_fd:
        raw_data = yaml_fd.read()

    data = yaml.load(raw_data)

    with open(json_file, 'w') as json_fd:
        json_fd.write(
            json.dumps(data, indent=4, separators=(',', ': '), sort_keys=True)
        )
        json_fd.write('\n')


def _find(basepath, extension='.yml'):
    basepath, dirs, files = next(os.walk(basepath))
    for filename in files:
        if filename.endswith(extension):
            yield os.path.join(basepath, filename)

    for dirname in dirs:
        for filename in _find(
            basepath=os.path.join(basepath, dirname),
            extension=extension,
        ):
            yield filename


def _generate_json_schemas():
    schemas_dir = os.path.join(
        os.path.dirname(__file__),
        'inspire_schemas/records'
    )
    for yaml_file in _find(basepath=schemas_dir, extension='.yml'):
        json_file = yaml_file.rsplit('.', 1)[0] + '.json'
        _yaml2json(yaml_file=yaml_file, json_file=json_file)


def do_setup(url=URL):
    _generate_json_schemas()
    setup(
        author='CERN',
        author_email='admin@inspirehep.net',
        description='Inspire JSON schemas and utilities to use them.',
        install_requires=[
            'autosemver',
            'jsonschema',
            'idutils',
            'pyyaml',
            'six',
        ],
        license='GPLv2',
        name='inspire-schemas',
        package_data={'': ['*.json', 'CHANGELOG', 'AUTHORS']},
        packages=find_packages(),
        setup_requires=['autosemver', 'pyyaml'],
        url=URL,
        bugtracker_url=URL + '/issues/',
        zip_safe=False,
        autosemver=True,
    )


if __name__ == '__main__':
    do_setup()
