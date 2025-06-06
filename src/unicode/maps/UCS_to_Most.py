#! /usr/bin/env python3

# This script's purpose is to generate
# UTF-8 <--> character code conversion tables from map files provided by
# the Unicode organization.

import sys
import enc_convutils

def main():
    """
    Main function to generate conversion tables.
    """
    this_script = 'src/unicode/maps/UCS_to_most.py'

    filename_map = {
        'WIN866': '../defs/CP866.TXT',
        'WIN874': '../defs/CP874.TXT',
        'WIN1250': '../defs/CP1250.TXT',
        'WIN1251': '../defs/CP1251.TXT',
        'WIN1252': '../defs/CP1252.TXT',
        'WIN1253': '../defs/CP1253.TXT',
        'WIN1254': '../defs/CP1254.TXT',
        'WIN1255': '../defs/CP1255.TXT',
        'WIN1256': '../defs/CP1256.TXT',
        'WIN1257': '../defs/CP1257.TXT',
        'WIN1258': '../defs/CP1258.TXT',
        'GBK': '../defs/CP936.TXT'
    }

    # Use command-line arguments if provided, otherwise process all charsets
    charsets = sys.argv[1:] if len(sys.argv) > 1 else sorted(filename_map.keys())

    for charset in sorted(charsets):
        if charset in filename_map:
            mapping = enc_convutils.read_source(filename_map[charset])
            enc_convutils.print_conversion_tables(this_script, charset, mapping)
        else:
            print(f"Warning: Unknown charset '{charset}' ignored.", file=sys.stderr)

if __name__ == '__main__':
    main()
