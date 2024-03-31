#!/usr/bin/env bash

set -x

srcdir="${1:-/usr/lib}"
outdir="target/sframe"

print_if_lib() {
    mime=$(file "$1" --mime | cut -d':' -f2 | cut -d';' -f1)
    mime=$(echo $mime)

    case "$mime" in
        application/x-object)           ;;
        application/x-pie-executable)   ;;
        application/x-executable)       ;;
        application/x-sharedlib)        ;;

        *)
            # echo "$1: $mime" 1>&2
            exit 0
            ;;
    esac

    echo "$1"
}

convert() {
    set -eu

    real="$1"
    base="$(basename "$real")"
    outdir="$2"

    echo "Converting $base"

    ./target/release/dwarf2sframe2 "$real" \
        --debug-dump \
        --warnings \
        -o "$outdir/$base.o" \
        > "$outdir/$base.log" 2>&1
    ./target/release/dwarfdump "$real" > "$outdir/$base.dwarf"
    ./target/release/sframedump "$outdir/$base.o" > "$outdir/$base.sframe"
    objdump -d "$real" --demangle=auto -F -Mintel > "$outdir/$base.asm"
}

export -f print_if_lib
export -f convert

mkdir -p "$outdir"
cargo build --release --bin dwarf2sframe2 --bin sframedump --bin dwarfdump

find "$srcdir" -type f -a -executable -print0 | \
    xargs -0 -n1 "-P$(nproc)" -- bash -c 'print_if_lib "$@"' -- | \
    uniq | \
    xargs    -n1 "-P$(nproc)" -- bash -c 'convert "$1" '"'$outdir'" --
