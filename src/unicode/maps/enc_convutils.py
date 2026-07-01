import sys
import re
from collections import defaultdict

# Constants used in the 'direction' field of the character maps
NONE = 0
TO_UNICODE = 1
FROM_UNICODE = 2
BOTH = 3

# Define the public API for this module
__all__ = ['NONE', 'TO_UNICODE', 'FROM_UNICODE',
           'BOTH', 'read_source', 'print_conversion_tables']


def ucs2utf(ucs):
    """
    Converts a UCS-4 code point to its UTF-8 representation as an integer.

    NOTE: This function is preserved from the original to maintain identical
    behavior, especially for edge cases like surrogate code points, which
    are handled differently by standard Python libraries.
    """
    if ucs <= 0x007f:
        return ucs
    elif 0x007f < ucs <= 0x07ff:
        return ((ucs & 0x003f) | 0x80) | (((ucs >> 6) | 0xc0) << 8)
    elif 0x07ff < ucs <= 0xffff:
        return (((ucs >> 12) | 0xe0) << 16) | \
               ((((ucs & 0x0fc0) >> 6) | 0x80) << 8) | \
               ((ucs & 0x003f) | 0x80)
    else:
        return (((ucs >> 18) | 0xf0) << 24) | \
               ((((ucs & 0x3ffff) >> 12) | 0x80) << 16) | \
               ((((ucs & 0x0fc0) >> 6) | 0x80) << 8) | \
               ((ucs & 0x003f) | 0x80)


def read_source(fname):
    """
    Common routine to read a source character map file.

    Args:
        fname (str): Input file name.

    Returns:
        list: A list of mapping dictionaries.
    """
    result = []
    try:
        with open(fname, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(None, 2)

                # Check for a valid two-code mapping line
                if len(parts) == 3 and parts[0].startswith('0x') and \
                   parts[1].startswith('0x') and parts[2].startswith('#'):

                    try:
                        code = int(parts[0], 16)
                        ucs = int(parts[1], 16)
                    except ValueError:
                        print(
                            f"READ ERROR: Invalid hex value at line {line_num} in {fname}: {line}", file=sys.stderr)
                        sys.exit(1)

                    out = {
                        'code': code,
                        'ucs': ucs,
                        'comment': parts[2],
                        'direction': BOTH,
                        'f': fname,
                        'l': line_num
                    }

                    # Ignore pure ASCII mappings
                    if out['code'] < 0x80 or out['ucs'] < 0x80:
                        continue

                    result.append(out)

                # Check for a single-code line to be ignored
                elif len(parts) >= 2 and parts[0].startswith('0x') and parts[1].startswith('#'):
                    continue

                else:
                    print(
                        f"READ ERROR: Malformed line {line_num} in {fname}: {line}", file=sys.stderr)
                    sys.exit(1)

    except FileNotFoundError:
        print(f"cannot open {fname}", file=sys.stderr)
        sys.exit(1)

    return result


def print_conversion_tables(this_script, csname, charset):
    """
    Outputs mapping tables for both to- and from-Unicode directions.
    """
    _print_conversion_tables_direction(
        this_script, csname, FROM_UNICODE, charset)
    _print_conversion_tables_direction(
        this_script, csname, TO_UNICODE, charset)


def _print_conversion_tables_direction(this_script, csname, direction, charset):
    """
    Generates and writes the C source for mapping tables in a specific direction.
    """
    if direction == TO_UNICODE:
        fname = f"{csname.lower()}_to_utf8.map"
        tblname = f"{csname.lower()}_to_unicode_tree"
        print(f"- Writing {csname}=>UTF8 conversion table: {fname}")
    else:
        fname = f"utf8_to_{csname.lower()}.map"
        tblname = f"{csname.lower()}_from_unicode_tree"
        print(f"- Writing UTF8=>{csname} conversion table: {fname}")

    # Separate mappings into regular and combined lists
    regular_map = {}
    combined_map = []
    for c in charset:
        if not (c['direction'] == direction or c['direction'] == BOTH):
            continue

        if 'ucs_second' in c:
            combined_map.append({
                'utf8': ucs2utf(c['ucs']),
                'utf8_second': ucs2utf(c['ucs_second']),
                'code': c['code'],
                'comment': c['comment'], 'f': c['f'], 'l': c['l']
            })
        else:
            src, dst = (c['code'], ucs2utf(c['ucs'])) if direction == TO_UNICODE else (
                ucs2utf(c['ucs']), c['code'])
            if src in regular_map:
                print(f"Error: duplicate source code on {c['f']}:{c['l']}: "
                      f"0x{src:04x} => 0x{regular_map[src]:04x}, 0x{dst:04x}", file=sys.stderr)
                sys.exit(1)
            regular_map[src] = dst

    try:
        with open(fname, 'w') as out:
            out.write(f"/* {fname} */\n")
            out.write(f"/* This file is generated by {this_script} */\n\n")

            _print_radix_table(out, tblname, regular_map)

            if combined_map:
                _print_combined_map(out, csname, combined_map, direction)

    except IOError:
        print(f"cannot open {fname}", file=sys.stderr)
        sys.exit(1)


def _print_combined_map(out, csname, table, direction):
    """Writes the C array for a combined character map."""
    if direction == TO_UNICODE:
        def sort_key(x): return x['code']
        struct_name = f"flb_local_to_utf_combined LUmap{csname}_combined"
        fields = ('code', 'utf8', 'utf8_second')
        formats = ('04x', '08x', '08x')
    else:  # FROM_UNICODE
        def sort_key(x): return (x['utf8'], x['utf8_second'])
        struct_name = f"flb_utf_to_local_combined ULmap{csname}_combined"
        fields = ('utf8', 'utf8_second', 'code')
        formats = ('08x', '08x', '04x')

    table.sort(key=sort_key)

    out.write("\n/* Combined character map */\n")
    out.write(f"static const {struct_name}[{len(table)}] = {{\n")

    for i, item in enumerate(table):
        comment = f"{item['f']}:{item['l']} {item['comment']}"
        values = ", ".join(
            [f"0x{item[field]:{fmt}}" for field, fmt in zip(fields, formats)])

        out.write(f"  /* {comment} */\n")
        out.write(f"  {{{values}}}")
        if i < len(table) - 1:
            out.write(",")
        out.write("\n")

    out.write("};\n")

# --- Radix Tree Generation ---


def _build_radix_trees(charmap):
    """Builds radix trees in memory from the character map."""
    trees = {
        1: {},
        2: defaultdict(dict),
        3: defaultdict(lambda: defaultdict(dict)),
        4: defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    }
    for in_char, out_char in charmap.items():
        if in_char <= 0xff:
            trees[1][in_char] = out_char
        elif in_char <= 0xffff:
            trees[2][in_char >> 8][in_char & 0xff] = out_char
        elif in_char <= 0xffffff:
            trees[3][in_char >> 16][(in_char >> 8) &
                                     0xff][in_char & 0xff] = out_char
        elif in_char <= 0xffffffff:
            trees[4][in_char >> 24][(in_char >> 16) & 0xff][(
                in_char >> 8) & 0xff][in_char & 0xff] = out_char
        else:
            raise ValueError(f"up to 4 byte code is supported: 0x{in_char:x}")
    return trees


def _build_segments_from_trees(trees):
    """Builds a sorted list of segments from the radix trees."""
    segments = []
    tree_info = [
        ("Single byte table", "1-byte", 1), ("Two byte table", "2-byte", 2),
        ("Three byte table", "3-byte", 3), ("Four byte table", "4-byte", 4)
    ]
    for header, label, depth in tree_info:
        if trees[depth]:
            segments.extend(_build_segments_from_tree(
                header, label, depth, trees[depth]))
    return segments


def _build_segments_from_tree(header, rootlabel, depth, treemap):
    """Helper to build a sorted list of segments from a single tree."""
    if not treemap:
        return []
    segments = _build_segments_recurse(
        header, rootlabel, "", 1, depth, treemap)
    segments.sort(key=lambda s: (s['level'], s['path']))  # Sort breadth-first
    return segments


def _build_segments_recurse(header, label, path, level, depth, treemap):
    """Recursively builds segments for the radix tree."""
    segments = []
    if level == depth:  # Leaf node
        segments.append({'header': f"{header}, leaf: {path}xx", 'label': label,
                         'level': level, 'depth': depth, 'path': path, 'values': treemap})
    else:  # Internal node
        children = {}
        for i, val in treemap.items():
            childpath = f"{path}{i:02x}"
            childlabel = f"{depth}-level-{level}-{childpath}"
            segments.extend(_build_segments_recurse(
                header, childlabel, childpath, level + 1, depth, val))
            children[i] = childlabel
        segments.append({'header': f"{header}, byte #{level}: {path}xx", 'label': label,
                         'level': level, 'depth': depth, 'path': path, 'values': children})
    return segments


def _process_segments(segments):
    """Calculates bounds, optimizes, and resolves offsets for all segments."""
    # Find min/max index for each level of each tree
    min_idx, max_idx = defaultdict(lambda: defaultdict(
        lambda: None)), defaultdict(lambda: defaultdict(lambda: None))
    for seg in segments:
        if not seg.get('values'):
            continue
        min_key, max_key = min(seg['values']), max(seg['values'])
        if min_idx[seg['depth']][seg['level']] is None or min_key < min_idx[seg['depth']][seg['level']]:
            min_idx[seg['depth']][seg['level']] = min_key
        if max_idx[seg['depth']][seg['level']] is None or max_key > max_idx[seg['depth']][seg['level']]:
            max_idx[seg['depth']][seg['level']] = max_key

    for seg in segments:
        seg['min_idx'] = min_idx.get(seg['depth'], {}).get(seg['level'], 0)
        seg['max_idx'] = max_idx.get(seg['depth'], {}).get(seg['level'], -1)

    # Prepend a dummy all-zeros map for invalid values
    widest_range = max((s['max_idx'] - s['min_idx']
                        for s in segments if s['max_idx'] != -1), default=-1)
    segments.insert(0, {'header': "Dummy map, for invalid values", 'min_idx': 0,
                        'max_idx': widest_range, 'label': "dummy map", 'values': {}})

    # Eliminate overlapping zeros between segments
    for j in range(len(segments) - 1):
        trail_zeros = 0
        for i in range(segments[j]['max_idx'], segments[j]['min_idx'] - 1, -1):
            if segments[j].get('values', {}).get(i):
                break
            trail_zeros += 1

        lead_zeros = 0
        for i in range(segments[j + 1]['min_idx'], segments[j + 1]['max_idx'] + 1):
            if segments[j + 1].get('values', {}).get(i):
                break
            lead_zeros += 1

        overlaid_zeros = min(trail_zeros, lead_zeros)
        segments[j]['overlaid_trail_zeros'] = overlaid_zeros
        segments[j]['max_idx'] -= overlaid_zeros

    # Replace label references with real offsets
    flatoff, segmap = 0, {}
    for seg in segments:
        seg['offset'] = flatoff
        if 'label' in seg:
            segmap[seg['label']] = flatoff
        flatoff += (seg['max_idx'] - seg['min_idx'] + 1)
    tblsize = flatoff

    for seg in segments:
        for i, val in list(seg.get('values', {}).items()):
            if isinstance(val, str):
                seg['values'][i] = segmap.get(val)
                if seg['values'][i] is None:
                    raise ValueError(f"no segment with label {val}")

    return segments, segmap, tblsize, min_idx, max_idx


def _print_radix_table(out, tblname, charmap):
    """Constructs and prints a radix tree from a character map."""
    if not charmap:
        return

    trees = _build_radix_trees(charmap)
    segments = _build_segments_from_trees(trees)
    if not segments:
        return

    segments, segmap, tblsize, min_idx, max_idx = _process_segments(segments)

    # Determine data type and formatting
    max_val = max((v for s in segments for v in s.get(
        'values', {}).values()), default=0)
    datatype = "uint32_t" if max_val > 0xffff else "uint16_t"

    if datatype == "uint16_t":
        vals_per_line, colwidth = 8, 4
    else:
        vals_per_line, colwidth = 4, 8

    # --- Print C Code ---
    bounds = {f'b{d}_{l}_lower': min_idx.get(d, {}).get(
        l, 0) for d in range(1, 5) for l in range(1, d+1)}
    upper_bounds = ({f'b{d}_{l}_upper': max_idx.get(d, {}).get(
        l, -1) + 1 for d in range(1, 5) for l in range(1, d+1)})

    for d in range(1, 5):
        for l in range(1, d + 1):
            upper = max_idx.get(d, {}).get(l, -1)
            if upper >= 256:
                upper_bounds[f'b{d}_{l}_upper'] = 0xff
            elif upper < 0:
                upper_bounds[f'b{d}_{l}_upper'] = 0x00
            else:
                upper_bounds[f'b{d}_{l}_upper'] = upper
    upper_bounds.update(upper_bounds)

    out.write(f"static const {datatype} {tblname}_table[{tblsize}];\n\n")
    out.write(f"static const flb_mb_radix_tree {tblname} = {{\n")
    out.write(f"  {tblname}_table,\n" if datatype ==
              "uint16_t" else "  NULL,\n")
    out.write(f"  {tblname}_table,\n" if datatype ==
              "uint32_t" else "  NULL,\n")
    out.write(f"""
  0x{segmap.get("1-byte", 0):04x}, 0x{bounds['b1_1_lower']:02x}, 0x{upper_bounds['b1_1_upper']:02x},
  0x{segmap.get("2-byte", 0):04x}, 0x{bounds['b2_1_lower']:02x}, 0x{upper_bounds['b2_1_upper']:02x}, 0x{bounds['b2_2_lower']:02x}, 0x{upper_bounds['b2_2_upper']:02x},
  0x{segmap.get("3-byte", 0):04x}, 0x{bounds['b3_1_lower']:02x}, 0x{upper_bounds['b3_1_upper']:02x}, 0x{bounds['b3_2_lower']:02x}, 0x{upper_bounds['b3_2_upper']:02x}, 0x{bounds['b3_3_lower']:02x}, 0x{upper_bounds['b3_3_upper']:02x},
  0x{segmap.get("4-byte", 0):04x}, 0x{bounds['b4_1_lower']:02x}, 0x{upper_bounds['b4_1_upper']:02x}, 0x{bounds['b4_2_lower']:02x}, 0x{upper_bounds['b4_2_upper']:02x}, 0x{bounds['b4_3_lower']:02x}, 0x{upper_bounds['b4_3_upper']:02x}, 0x{bounds['b4_4_lower']:02x}, 0x{upper_bounds['b4_4_upper']:02x}
}};\n\n""")

    out.write(f"static const {datatype} {tblname}_table[{tblsize}] = {{\n")
    off = 0
    for seg in segments:
        out.write(f"\n  /*** {seg['header']} - offset 0x{off:05x} ***/\n\n")
        i = seg['min_idx']
        while i <= seg['max_idx']:
            line_vals = [f" 0x{seg.get('values', {}).get(j, 0):0{colwidth}x}"
                         for j in range(i, min(i + vals_per_line, seg['max_idx'] + 1))]
            out.write(f"  /* {i:02x} */{','.join(line_vals)}")
            if off + len(line_vals) < tblsize:
                out.write(",")
            out.write("\n")
            i += len(line_vals)
            off += len(line_vals)
        if seg.get('overlaid_trail_zeros'):
            out.write(
                f"    /* {seg['overlaid_trail_zeros']} trailing zero values shared with next segment */\n")

    if off != tblsize:
        raise RuntimeError(f"table size mismatch! {off} != {tblsize}")
    out.write("};\n")
