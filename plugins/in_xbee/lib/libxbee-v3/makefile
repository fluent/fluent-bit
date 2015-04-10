# get hold of the build system
include make/buildsys.mk

# the configuration can be found in config.mk after running `make configure`

.PHONY: all configure new clean distclean

all: $(LIB_OUT)

configure: config.mk
	@true

new: clean
	@$(MAKE) all

clean:
ifneq ($(CLEAN_FILES),)
	$(RM) $(CLEAN_FILES)
endif

distclean: clean
	$(RM) $(patsubst %,.%.dir,$(CONSTRUCTIONDIRS))
	$(RMDIR) $(CONSTRUCTIONDIRS)
ifneq ($(DISTCLEAN_FILES),)
	$(RM) $(DISTCLEAN_FILES)
endif

# get hold of the build rules
include $(firstword $(BUILD_RULES))

# get hold of the install rules if there are any
ifneq ($(INSTALL_RULES),)
include $(firstword $(INSTALL_RULES))
endif

.PHONY: install uninstall

install: $(INSTALL_FILES)

uninstall:
	rm -rf $(INSTALL_FILES)
