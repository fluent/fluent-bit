#! /usr/bin/env python3
# Note: This script requires CP950.TXT, which must be obtained from
# Unicode, Inc. (https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/)
# to function correctly.
#

import sys
import enc_convutils

def main():
    """
    Main function to generate BIG5 conversion tables.
    """
    this_script = 'src/unicode/maps/UCS_to_BIG5.py'

    # Load BIG5.TXT
    all_mappings = enc_convutils.read_source("../defs/BIG5.TXT")

    # Load CP950.TXT to get additional characters
    cp950_mappings = enc_convutils.read_source("../defs/CP950.TXT")

    for item in cp950_mappings:
        code = item['code']
        ucs = item['ucs']

        # Pick only the ETEN extended characters in the range 0xf9d6 - 0xf9dc
        if (code >= 0x80 and ucs >= 0x0080 and
            code >= 0xf9d6 and code <= 0xf9dc):
            all_mappings.append(item)

    for item in all_mappings:
        # BIG5.TXT maps several BIG5 characters to U+FFFD. The UTF-8 to BIG5
        # mapping can contain only one of them. For historical reasons, we
        # map the first one (0xA15A) and set the others to one-way.
        if item['ucs'] == 0xFFFD and item['code'] != 0xA15A:
            item['direction'] = enc_convutils.TO_UNICODE

    # Output the final conversion tables
    enc_convutils.print_conversion_tables(this_script, "BIG5", all_mappings)

if __name__ == '__main__':
    main()
