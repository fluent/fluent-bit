LIBSUBDIRS=	src src-cpp

CHECK_FILES+=	CONFIGURATION.md \
		examples/rdkafka_example examples/rdkafka_performance \
		examples/rdkafka_example_cpp

DOC_FILES+=	LICENSE LICENSES.txt INTRODUCTION.md README.md \
		CONFIGURATION.md STATISTICS.md CHANGELOG.md

PKGNAME?=	librdkafka
VERSION?=	$(shell python3 packaging/get_version.py src/rdkafka.h)

# Jenkins CI integration
BUILD_NUMBER ?= 1

# Skip copyright check in the following paths
MKL_COPYRIGHT_SKIP?=^(tests|packaging)


.PHONY:

all: mklove-check libs CONFIGURATION.md check TAGS

include mklove/Makefile.base

libs:
	@(for d in $(LIBSUBDIRS); do $(MAKE) -C $$d || exit $?; done)

CONFIGURATION.md: src/rdkafka.h examples
	@printf "$(MKL_YELLOW)Updating $@$(MKL_CLR_RESET)\n"
	@echo "# Configuration properties" > CONFIGURATION.md.tmp
	@(examples/rdkafka_performance -X list | \
		sed 's/||/\\|\\|/g' >> \
		CONFIGURATION.md.tmp; \
		cmp CONFIGURATION.md CONFIGURATION.md.tmp || \
		mv -f CONFIGURATION.md.tmp CONFIGURATION.md; \
		rm -f CONFIGURATION.md.tmp)

file-check: CONFIGURATION.md LICENSES.txt examples
check: file-check
	@(for d in $(LIBSUBDIRS); do $(MAKE) -C $$d $@ || exit $?; done)

install-subdirs:
	@(for d in $(LIBSUBDIRS); do $(MAKE) -C $$d install || exit $?; done)

install: install-subdirs doc-install

uninstall-subdirs:
	@(for d in $(LIBSUBDIRS); do $(MAKE) -C $$d uninstall || exit $?; done)

uninstall: uninstall-subdirs doc-uninstall

examples tests: .PHONY libs
	$(MAKE) -C $@

docs:
	doxygen Doxyfile
	@echo "Documentation generated in staging-docs"

clean-docs:
	rm -rf staging-docs

clean:
	@$(MAKE) -C tests $@
	@$(MAKE) -C examples $@
	@(for d in $(LIBSUBDIRS); do $(MAKE) -C $$d $@ ; done)

distclean: clean deps-clean
	./configure --clean
	rm -f config.log config.log.old

archive:
	git archive --prefix=$(PKGNAME)-$(VERSION)/ \
		-o $(PKGNAME)-$(VERSION).tar.gz HEAD
	git archive --prefix=$(PKGNAME)-$(VERSION)/ \
		-o $(PKGNAME)-$(VERSION).zip HEAD

rpm: distclean
	$(MAKE) -C packaging/rpm

LICENSES.txt: .PHONY
	@(for i in LICENSE LICENSE.*[^~] ; do (echo "$$i" ; echo "--------------------------------------------------------------" ; cat $$i ; echo "" ; echo "") ; done) > $@.tmp
	@cmp $@ $@.tmp || mv -f $@.tmp $@ ; rm -f $@.tmp


TAGS: .PHONY
	@(if which etags >/dev/null 2>&1 ; then \
		echo "Using etags to generate $@" ; \
		git ls-tree -r --name-only HEAD | egrep '\.(c|cpp|h)$$' | \
			etags -f $@.tmp - ; \
		cmp $@ $@.tmp || mv $@.tmp $@ ; rm -f $@.tmp ; \
	 elif which ctags >/dev/null 2>&1 ; then \
		echo "Using ctags to generate $@" ; \
		git ls-tree -r --name-only HEAD | egrep '\.(c|cpp|h)$$' | \
			ctags -e -f $@.tmp -L- ; \
		cmp $@ $@.tmp || mv $@.tmp $@ ; rm -f $@.tmp ; \
	fi)

coverity: Makefile.config
	@(which cov-build >/dev/null 2>&1 || echo "Make sure coverity../bin is in your PATH")
	@(cd src && \
	 make clean && \
	 (rm -rf cov-int cov-librdkafka.tgz cov-build || true) && \
	 cov-build --dir cov-int make -j && \
	 tar cvzf ../cov-librdkafka.tgz cov-int && \
	 printf "$(MKL_GREEN)Now upload cov-librdkafka.tgz to Coverity for analysis$(MKL_CLR_RESET)\n")


style-check:
	@(packaging/tools/style-format.sh \
		$$(git ls-tree -r --name-only HEAD | egrep '\.(c|cpp|h|py)$$') )

style-check-changed:
	@(packaging/tools/style-format.sh \
		$$( (git diff --name-only ; git diff --name-only --staged) | egrep '\.(c|cpp|h|py)$$'))

style-fix:
	@(packaging/tools/style-format.sh --fix \
		$$(git ls-tree -r --name-only HEAD | egrep '\.(c|cpp|h|py)$$'))

style-fix-changed:
	@(packaging/tools/style-format.sh --fix \
		$$( (git diff --name-only ; git diff --name-only --staged) | egrep '\.(c|cpp|h|py)$$'))

