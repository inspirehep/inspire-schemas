#!/usr/bin/env sh
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


pydocstyle --explain --source inspire_schemas tests && \
isort -rc -c --skip docs/conf.py -df **/*.py && \
pytest \
    --pep8 \
    --cov=inspire_schemas \
    --cov-report=term-missing \
    -vv \
    "$@" \
    tests \
    inspire_schemas && \
sphinx-build -qnN docs docs/_build/html && \
sphinx-build -qnN -b doctest docs docs/_build/doctest
