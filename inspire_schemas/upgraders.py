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

"""Upgraders utilities."""

import re
import semver

from .utils import get_schema_and_revision, LATEST_SCHEMA_REVISIONS



def build_ledger():
    return {
        'authors': [
            ('0.0.1', first_revision_rule)
        ],
        'conferences': [
            ('0.0.1', first_revision_rule)
        ],
        'data': [
            ('0.0.1', first_revision_rule)
        ],
        'experiments': [
            ('0.0.1', first_revision_rule)
        ],
        'literature': [
            ('0.0.1', first_revision_rule)
        ],
        'institutions': [
            ('0.0.1', first_revision_rule)
        ],
        'jobs': [
            ('0.0.1', first_revision_rule)
        ],
        'journals': [
            ('0.0.1', first_revision_rule)
        ],
    }


LEDGERS = build_ledger()


def upgrade(json):
    schema, current_revision = get_schema_and_revision(json)
    for revision, rule in LEDGERS['schema']:
        if semver.compare(revision, current_revision, loose=False) > 0:
            json = rule(json)
    json['schema'] = '{schema}-{revision}.json'.format(
        schema=schema,
        revision=LATEST_SCHEMA_REVISIONS[schema]
    )
    return json


def first_revision_rule(json):
    """Upgrade records for the first time.

    Upgrades records for the first time by introducing the new concept of
    schema revision.
    """
    json['$schema'] = json['$schema'].replace('.json', '-0.0.1.json')
    return json
