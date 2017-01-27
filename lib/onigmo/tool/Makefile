UNICODE_VERSION = 9.0.0

PROP_FILES = \
	    $(UNICODE_VERSION)/Blocks.txt \
	    $(UNICODE_VERSION)/DerivedAge.txt \
	    $(UNICODE_VERSION)/DerivedCoreProperties.txt \
	    $(UNICODE_VERSION)/PropertyAliases.txt \
	    $(UNICODE_VERSION)/PropertyValueAliases.txt \
	    $(UNICODE_VERSION)/PropList.txt \
	    $(UNICODE_VERSION)/Scripts.txt \
	    $(UNICODE_VERSION)/UnicodeData.txt \
	    $(UNICODE_VERSION)/GraphemeBreakProperty.txt

CASEFOLD_FILES = \
	    $(UNICODE_VERSION)/CaseFolding.txt \
	    $(UNICODE_VERSION)/UnicodeData.txt \
	    $(UNICODE_VERSION)/SpecialCasing.txt


update: casefold.h name2ctype.h
	cp casefold.h name2ctype.h ../enc/unicode

download:
	./download-ucd.sh $(UNICODE_VERSION)


casefold.h: $(CASEFOLD_FILES)
	$(RUBY) ./case-folding.rb -m $(UNICODE_VERSION) -o casefold.h

name2ctype.h: $(PROP_FILES)
	$(RUBY) ./enc-unicode.rb --header $(UNICODE_VERSION) > name2ctype.h


clean:
	-rm -f casefold.h name2ctype.kwd name2ctype.h
	-rm -f $(PROP_FILES) $(CASEFOLD_FILES)
	-rmdir $(UNICODE_VERSION)
