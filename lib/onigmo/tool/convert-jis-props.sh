#!/bin/sh

# Convert props.kwd to props.h using GNU gperf.
#
# Usage:
#   ./tool/convert-jis-props.sh enc/jis/props.kwd enc/jis/props.h

GPERF_VERSION=`gperf -v | head -n1 | sed -e 's/^GNU gperf \([0-9]\+\)\.\([0-9]\+.*\)$/\1 \2/' | xargs printf '%02d%02d'`
if [ $GPERF_VERSION -ge '0301' ]; then
    # static const struct enc_property *onig_jis_property(const char *str, unsigned int len);
    GPERF_REPLACE='s/\(onig_jis_property([^,]\+, \).\+\( len)\)/\1size_t\2/'
else
    GPERF_REPLACE='#'
fi

JIS_PROPS_OPTIONS='-k1,3 -7 -c -j1 -i1 -t -C -P -t --ignore-case -H onig_jis_property_hash -Q onig_jis_property_pool -N onig_jis_property'

gperf $JIS_PROPS_OPTIONS $1 | sed "$GPERF_REPLACE" | \
    sed 's/(int)(\(long\|size_t\))&((\([a-zA-Z_0-9 ]*[a-zA-Z_0-9]\) *\*)0)->\([a-zA-Z0-9_]*\),/(char)offsetof(\2, \3),/g' > $2
