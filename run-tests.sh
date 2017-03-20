#!/bin/bash
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


clean_dir() {
    local to_clean="${1?No dir to clean passed}"
    [[ -d "$to_clean" ]] \
    && [[ "$to_clean" != "/" ]] \
    && rm -rf "$to_clean"
    return 0
}


check_prettified() {
    local dir_to_check="${1?No dir to check passed}"
    local tmpdir="$(mktemp -d 'Prettified_check.XXXXX' --tmpdir)"
    trap "clean_dir '$tmpdir'" TERM EXIT
    cp -a "$dir_to_check" "$tmpdir/"
    scripts/prettify_json.sh "$tmpdir"
    diff \
        --side-by-side \
        --recursive \
        --brief \
        "$tmpdir/${dir_to_check##*/}" "$dir_to_check"
    res="$?"
    if [[ "$res" != "0" ]]; then
        echo "PRETTIFY::ERROR:: Found unprettified json files, please run" \
            "the scripts/prettify_json.sh script on the repo to fix."
    fi
    return "$res"
}


isort -rc -c --skip docs/conf.py -df **/*.py && \
pytest \
    --pep8 \
    --cov=inspire_schemas \
    --cov-report=term-missing \
    --capture=sys \
    -vv \
    "$@" \
    tests \
    inspire_schemas && \
sphinx-build -qnN docs docs/_build/html && \
sphinx-build -qnN -b doctest docs docs/_build/doctest && \
check_prettified "${0%/*}"
