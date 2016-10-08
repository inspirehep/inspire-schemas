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

import os
import subprocess

from setuptools import setup, find_packages


def check_output(args):
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()

    if proc.returncode:
        raise RuntimeError(
            'Failed to run %s\nrc=%s\nstdout=\n%sstderr=%s' %
            (args, proc.returncode, stdout, stderr)
        )

    return stdout.decode()


def get_version(project_dir=os.curdir):
    """
    Retrieves the version of the package, from the PKG-INFO file or generates
    it with the version script
    Returns:
        str: Version for the package
    Raises:
        RuntimeError: If the version could not be retrieved
    """
    if (
        'INSPIRE_SCHEMAS_VERSION' in os.environ and
        os.environ['INSPIRE_SCHEMAS_VERSION']
    ):
        return os.environ['INSPIRE_SCHEMAS_VERSION']

    version = None
    pkg_info_file = os.path.join(project_dir, 'PKG-INFO')
    version_manager = os.path.join(project_dir, 'scripts/version_manager.py')
    if os.path.exists(pkg_info_file):
        with open(pkg_info_file) as info_fd:
            for line in info_fd.readlines():
                if line.startswith('Version: '):
                    version = line.split(' ', 1)[-1]

    elif os.path.exists(version_manager):
        version = check_output(
            [version_manager, project_dir, 'version']
        ).strip()

    if version is None:
        raise RuntimeError('Failed to get package version')

    # py3 compatibility step
    if not isinstance(version, str) and isinstance(version, bytes):
        version = version.decode()

    return version


def get_authors(project_dir=os.curdir):
    """
    Retrieves the authors list, from the AUTHORS file (if in a package) or
    generates it with the version script
    Returns:
        list(str): List of authors
    Raises:
        RuntimeError: If the authors could not be retrieved
    """
    authors = set()
    pkg_info_file = os.path.join(project_dir, 'PKG-INFO')
    authors_file = os.path.join(project_dir, 'AUTHORS')
    version_manager = os.path.join(project_dir, 'scripts/version_manager.py')
    if os.path.exists(pkg_info_file) and os.path.exists(authors_file):
        with open(authors_file) as authors_fd:
            authors = set(authors_fd.read().splitlines())

    elif os.path.exists(version_manager):
        authors = set(check_output(
            [version_manager, project_dir, 'authors']
        ).strip().splitlines())

    return authors


def get_changelog(project_dir=os.curdir):
    """
    Retrieves the changelog, from the CHANGELOG file (if in a package) or
    generates it with the version script
    Returns:
        str: changelog
    Raises:
        RuntimeError: If the changelog could not be retrieved
    """
    changelog = ''
    pkg_info_file = os.path.join(project_dir, 'PKG-INFO')
    changelog_file = os.path.join(project_dir, 'CHANGELOG')
    version_manager = os.path.join(project_dir, 'scripts/version_manager.py')
    if os.path.exists(pkg_info_file) and os.path.exists(changelog_file):
        with open(changelog_file) as changelog_fd:
            changelog = changelog_fd.read()

    elif os.path.exists(version_manager):
        changelog = check_output(
            [version_manager, project_dir, 'changelog']
        ).strip()

    return changelog


if __name__ == '__main__':
    with open('AUTHORS', 'w') as authors_fd:
        authors_fd.write('\n'.join(get_authors()))

    with open('CHANGELOG', 'w') as changelog_fd:
        changelog_fd.write(get_changelog())

    setup(
        author='CERN',
        author_email='admin@inspirehep.net',
        description='Inspire JSON schemas and utilities to use them.',
        install_requires=['jsonschema'],
        license='GPLv2',
        name='inspire-schemas',
        package_data={'': ['*.json', 'CHANGELOG', 'AUTHORS']},
        packages=find_packages(),
        url='https://github.com/inspirehep/inspire-schemas',
        version=get_version(),
        zip_safe=False,
    )
