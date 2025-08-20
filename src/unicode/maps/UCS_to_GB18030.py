#! /usr/bin/env python3
# Note: The script's purpose is to generate
# UTF-8 <--> GB18030 conversion tables from map files provided by
# the ICU project.
#

import sys
import re
import enc_convutils

def main():
    """
    Main function to generate GB18030 conversion tables.
    """
    this_script = 'src/unicode/maps/UCS_to_GB18030.py'
    in_file = "../defs/gb-18030-2000.xml"

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

    enc_convutils.print_conversion_tables(this_script, "GB18030", mapping)

if __name__ == '__main__':
    main()
