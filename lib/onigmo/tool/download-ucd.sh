#!/bin/bash

files='Blocks.txt CaseFolding.txt DerivedAge.txt DerivedCoreProperties.txt PropertyAliases.txt PropertyValueAliases.txt PropList.txt Scripts.txt SpecialCasing.txt UnicodeData.txt auxiliary/GraphemeBreakProperty.txt'
emoji_files='emoji-data.txt'

if [ -z $1 ] || [ -z $2 ]; then
	echo "usage: $0 UNICODE_VERSION EMOJI_VERSION"
	exit 1
fi
UNICODE_VERSION=$1
EMOJI_VERSION=$2

# remove old files
if [ -d $UNICODE_VERSION ]; then
	cd $UNICODE_VERSION
	rm -f $files $emoji_files
	rm -f GraphemeBreakProperty.txt
	cd -
fi

mkdir -p $UNICODE_VERSION/auxiliary
cd $UNICODE_VERSION

for i in $files; do
	echo http://www.unicode.org/Public/${UNICODE_VERSION}/ucd/$i
done | xargs wget
mv GraphemeBreakProperty.txt auxiliary
for i in $emoji_files; do
	echo http://www.unicode.org/Public/emoji/${EMOJI_VERSION}/$i
done | xargs wget
