#!/bin/bash -e
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
prepare() {
    rm -rf dist
    python setup.py sdist
    pushd dist
    tar xzf inspire-schemas-*.tar.gz
    popd
}


yml_files() {
    find inspire_schemas/records -iname \*.yml
}


main() {
    local yml_file \
        json_file \
        pkg_dir \
        missing_files \
        missing_file

    prepare &>/dev/null
    pkg_dir=$(find dist -maxdepth 1 -iname inspire-schemas\* -type d)

    missing_files=()
    for yml_file in $(yml_files); do
        json_file="${pkg_dir}/${yml_file%.yml}.json"
        if ! [[ -e "$json_file" ]]; then
            missing_files+=("$json_file")
        fi
    done

    if [[ $missing_files ]]; then
        echo "ERROR: Missing the json files:" >&2
        for missing_file in "${missing_files[@]}"; do
            echo "    $missing_file" >&2
        done
        return 1
    fi
    return 0
}


main "$@"
