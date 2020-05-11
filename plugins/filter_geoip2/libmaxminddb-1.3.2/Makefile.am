
include_HEADERS = include/maxminddb.h

nodist_include_HEADERS = include/maxminddb_config.h

SUBDIRS = \
  src     \
  bin

if TESTS
SUBDIRS += \
  t
endif

EXTRA_DIST = doc t Changes.md LICENSE NOTICE README.md projects/VS12 projects/VS12-tests
dist-hook:
	dev-bin/make-man-pages.pl $(distdir)
	find $(distdir) -name '.git*' | xargs rm -fr

safedist: clean dist
	tmpdir="$${TMPDIR-/tmp}/safedist-$$$$" \
	  && mkdir "$$tmpdir" \
	  && tar -xvf $(distdir).tar.gz --directory "$$tmpdir" \
	  && $(am__cd) "$$tmpdir/$(distdir)" \
	  && ./configure \
	  && make -j 4 check

man1_MANS = man/man1/*.1

man3_MANS = man/man3/*.3

man/man1/*.1:
	if [ ! -f man/man1/mmdblookup.1 ]; then mkdir -p man/man1 && touch man/man1/mmdblookup.1; fi

man/man3/*.3:
	if [ ! -f man/man3/libmaxminddb.3 ]; then mkdir -p man/man3 && touch man/man3/libmaxminddb.3; fi

release:
	dev-bin/make-release.sh

.PHONY: man/man1/*.1 man/man3/*.3 release
