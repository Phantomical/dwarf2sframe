#!/usr/bin/env bash

srcdir="$1"
outdir="target/sframe"

mkdir -p "$outdir"
cargo build --release --bin dwarf2sframe2 --bin sframedump --bin dwarfdump

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

export -f convert

for f in "$srcdir"/*.so; do
    real="$(readlink -f "$f")"

    if [ -z "$real" ]; then
        real="$f"
    fi

    sem --id $$ -j+0 convert "$real" "$outdir"
done

sem --id $$ --wait
