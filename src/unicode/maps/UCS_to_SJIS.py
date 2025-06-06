#! /usr/bin/env python3
# Note: This script requires CP932.TXT, which must be obtained from
# Unicode, Inc. (https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/)
# to function correctly.
#

import sys
import enc_convutils

# --- Main execution ---
def main():
    """
    Main function to generate the SJIS conversion tables.
    """
    this_script = 'src/unicode/maps/UCS_to_SJIS.py'

    # Attempt to read the source mapping file.
    try:
        mapping = enc_convutils.read_source("../defs/CP932.TXT")
    except SystemExit:
        print(
            "\nError: Could not read CP932.TXT.\n"
            "Please download it from the Unicode Consortium's website and place it "
            "in the same directory as this script.",
            file=sys.stderr)
        sys.exit(1)


    # Define a set of SJIS codes to be excluded from the UTF8=>SJIS conversion.
    # These mappings will only be used for SJIS=>UTF8.
    reject_sjis = set()
    reject_sjis.update(range(0xed40, 0xeefc + 1))
    reject_sjis.update(range(0x8754, 0x875d + 1))
    reject_sjis.update([0x878a, 0x8782, 0x8784, 0xfa5b, 0xfa54])
    reject_sjis.update(range(0x8790, 0x8792 + 1))
    reject_sjis.update(range(0x8795, 0x8797 + 1))
    reject_sjis.update(range(0x879a, 0x879c + 1))

    # Update the direction for the rejected SJIS codes.
    for item in mapping:
        if item['code'] in reject_sjis:
            item['direction'] = enc_convutils.TO_UNICODE

    # Define additional mappings to be added for the UTF8=>SJIS conversion.
    # The 'l' (line number) is set to 0 as a placeholder.
    additional_mappings = [
        {'direction': enc_convutils.FROM_UNICODE, 'ucs': 0x203e, 'code': 0x7e,   'comment': '# OVERLINE', 'f': this_script, 'l': 0},
    ]

    # Add the new mappings to the list.
    mapping.extend(additional_mappings)

    # Generate and print the final conversion tables.
    enc_convutils.print_conversion_tables(this_script, "SJIS", mapping)

if __name__ == "__main__":
    main()
