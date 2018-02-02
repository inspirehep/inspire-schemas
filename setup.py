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
from setuptools.command import develop, install, sdist


URL = 'https://github.com/inspirehep/inspire-schemas'


class CustomSdist(sdist.sdist):

    def run(self, *args, **kwargs):
        _generate_json_schemas()
        # sdist is not a new class object, we can't use super
        return sdist.sdist.run(self, *args, **kwargs)


class CustomInstall(install.install):

    def run(self, *args, **kwargs):
        _generate_json_schemas()
        # install is not a new class object, we can't use super
        return install.install.run(self, *args, **kwargs)


class CustomDevelop(develop.develop):

    def run(self, *args, **kwargs):
        _generate_json_schemas()
        # develop is not a new class object, we can't use super
        return develop.develop.run(self, *args, **kwargs)


def _resolve_json_schema(json_schema, path):
    import yaml

    if isinstance(json_schema, list):
        json_schema = [
            _resolve_json_schema(item, path) for item in json_schema
        ]
    elif isinstance(json_schema, dict):
        for key in json_schema:
            if key == '$ref' and not isinstance(json_schema[key], dict):
                subschema_path = os.path.join(path, json_schema[key])
                subschema_path = os.path.splitext(subschema_path)[0]
                with open(subschema_path+'.yml', 'rb') as yaml_fd:
                    raw_data = yaml_fd.read()
                data = yaml.load(raw_data)
                data = _resolve_json_schema(data, os.path.join(path, os.path.dirname(json_schema[key])))
                return data
            else:
                json_schema[key] = _resolve_json_schema(json_schema[key], path)
    return json_schema


def _yaml2json(yaml_file, json_file):
    import yaml

    with open(yaml_file, 'rb') as yaml_fd:
        raw_data = yaml_fd.read()
    data = yaml.load(raw_data)
    with open(json_file, 'w') as json_fd:
        json.dump(
            data, json_fd, indent=4, separators=(',', ': '), sort_keys=True
        )
        json_fd.write('\n')

    path = os.path.dirname(yaml_file)
    resolved_json_object = _resolve_json_schema(data, path)
    resolved_record = json_file.replace('records', 'resolved_records')
    with open(resolved_record, 'w') as json_fd:
        json.dump(
            resolved_json_object,
            json_fd,
            indent=4,
            separators=(',', ': '),
            sort_keys=True,
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


build_requires = [
    'autosemver',
    'pyyaml',
]

tests_require = [
    'check-manifest',
    'coverage',
    'isort~=4.0,>=4.3.0',
    'pytest-cache',
    'pytest-cov',
    'pytest-pep8',
    'pytest',
    'mock',
    'idutils',
]

docs_require = [
    'jsonschema2rst>=0.0.8',
    'Sphinx',
]

extras_require = {
    'docs': docs_require,
    'tests': tests_require,
}


def do_setup():

    setup(
        author='CERN',
        author_email='admin@inspirehep.net',
        cmdclass={
            'sdist': CustomSdist,
            'install': CustomInstall,
            'develop': CustomDevelop,
        },
        description='Inspire JSON schemas and utilities to use them.',
        install_requires=[
            'Unidecode~=1.0,>=1.0.22',
            'autosemver',
            'jsonschema',
            'idutils',
            'inspire-utils~=2.0,>=2.0.0',
            'isodate',
            'pyyaml',
            'rfc3987',
            'six',
        ],
        tests_require=tests_require,
        extras_require=extras_require,
        build_requires=build_requires,
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
