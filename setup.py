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

"""INSPIRE schemas and related tools bundle."""

from setuptools import setup, find_packages

from autosemver.packaging import (
    get_authors,
    get_current_version,
    get_changelog,
)

URL = 'https://github.com/inspirehep/inspire-schemas'

if __name__ == '__main__':
    with open('AUTHORS', 'w') as authors_fd:
        authors_fd.write('\n'.join(get_authors()))

    with open('CHANGELOG', 'w') as changelog_fd:
        changelog_fd.write(get_changelog(bugtracker_url=URL + '/issues/'))

    setup(
        author='CERN',
        author_email='admin@inspirehep.net',
        description='Inspire JSON schemas and utilities to use them.',
        install_requires=['autosemver', 'jsonschema'],
        license='GPLv2',
        name='inspire-schemas',
        package_data={'': ['*.json', 'CHANGELOG', 'AUTHORS']},
        packages=find_packages(),
        url=URL,
        version=get_current_version(project_name='inspire-schemas'),
        zip_safe=False,
    )
