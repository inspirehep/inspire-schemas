#!/bin/bash -e


prettify() {
    local orig="${1?}"
    python -m json.tool "$orig" > "$orig.tmp"
    mv "$orig.tmp" "$orig"
}


main() {
    local dir_to_prettify="${1:-.}"
    # Export also the prettify function, so we can use them with find
    export -f prettify
    find \
        "$dir_to_prettify" \
        -iname \*.json \
        -exec bash -c 'prettify "$0"' {} \;
}


main "$@"
