#!/bin/bash -e
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
