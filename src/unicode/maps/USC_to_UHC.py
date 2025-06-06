#! /usr/bin/env python3
# Note: This script requires CP950.TXT, which must be obtained from
# Unicode, Inc. (https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/)
# to function correctly.
#

import sys
import re
import enc_convutils

def main():
    """
    Main function to generate UHC conversion tables.
    """
    this_script = 'src/unicode/maps/UCS_to_UHC.py'
    in_file = "../defs/windows-949-2000.xml"

    mapping = []

    line_regex = re.compile(r'<a u="([0-9A-F]+)" b="([0-9A-F ]+)"')

    try:
        with open(in_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = line_regex.search(line)
                if not match:
                    continue

                u_str, c_str = match.groups()
                c_str = c_str.replace(" ", "")

                ucs = int(u_str, 16)
                code = int(c_str, 16)

                if code == 0x0080 or code == 0x00FF:
                    continue

                if code >= 0x80 and ucs >= 0x0080:
                    mapping.append({
                        'ucs': ucs,
                        'code': code,
                        'direction': enc_convutils.BOTH,
                        'f': in_file,
                        'l': line_num
                    })
    except FileNotFoundError:
        print(f"cannot open {in_file}", file=sys.stderr)
        sys.exit(1)

    # One extra character that's not in the source file.
    mapping.append({
        'direction': enc_convutils.BOTH,
        'code': 0xa2e8,
        'ucs': 0x327e,
        'comment': '# CIRCLED HANGUL IEUNG U',
        'f': this_script,
        'l': 'N/A'
    })

    enc_convutils.print_conversion_tables(this_script, "UHC", mapping)

if __name__ == '__main__':
    main()
