UNICODE_VERSION = 12.1.0
EMOJI_VERSION = 12.0

PROP_FILES = \
	    $(UNICODE_VERSION)/Blocks.txt \
	    $(UNICODE_VERSION)/DerivedAge.txt \
	    $(UNICODE_VERSION)/DerivedCoreProperties.txt \
	    $(UNICODE_VERSION)/PropertyAliases.txt \
	    $(UNICODE_VERSION)/PropertyValueAliases.txt \
	    $(UNICODE_VERSION)/PropList.txt \
	    $(UNICODE_VERSION)/Scripts.txt \
	    $(UNICODE_VERSION)/UnicodeData.txt \
	    $(UNICODE_VERSION)/auxiliary/GraphemeBreakProperty.txt \
	    $(UNICODE_VERSION)/emoji-data.txt

CASEFOLD_FILES = \
	    $(UNICODE_VERSION)/CaseFolding.txt \
	    $(UNICODE_VERSION)/UnicodeData.txt \
	    $(UNICODE_VERSION)/SpecialCasing.txt

update: update-unicode-header update-jis-header update-doc

update-unicode-header: casefold.h name2ctype.h
	cp casefold.h name2ctype.h ../enc/unicode

update-jis-header: ../enc/jis/props.kwd
	cd .. && ./tool/convert-jis-props.sh enc/jis/props.kwd enc/jis/props.h && cd -

update-doc: $(PROP_FILES) update-doc.py
	$(PYTHON) ./update-doc.py $(UNICODE_VERSION) > ../doc/UnicodeProps.txt

download:
	./download-ucd.sh $(UNICODE_VERSION) $(EMOJI_VERSION)


casefold.h: $(CASEFOLD_FILES) case-folding.rb
	$(RUBY) ./case-folding.rb -m $(UNICODE_VERSION) -o casefold.h

name2ctype.h: $(PROP_FILES) enc-unicode.rb
	$(RUBY) ./enc-unicode.rb --header $(UNICODE_VERSION) > name2ctype.h || rm -f name2ctype.h


clean:
	-rm -f casefold.h name2ctype.kwd name2ctype.h
	-rm -f $(PROP_FILES) $(CASEFOLD_FILES)
	-rm -f GraphemeBreakProperty.txt
	-rmdir $(UNICODE_VERSION)/auxiliary
	-rmdir $(UNICODE_VERSION)
