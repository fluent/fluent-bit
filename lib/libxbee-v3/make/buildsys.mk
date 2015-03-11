### the main build system

include make/libconfig.mk
include make/os_detect.mk

### some default values
OBJEXT?=.o
DEPEXT?=.d
COMMA?=,

ifeq ($(wildcard config.mk),)
ifeq ($(filter configure,$(MAKECMDGOALS)),)
$(error please run `make configure` first)
endif
endif

-include config.mk


.PRECIOUS: .%.dir

config.mk:| $(DEFCONFIG)
	cp $(firstword $|) $@

.%.dir:
	$(MKDIR)
	@touch $@

### generate a list of the core sources (excluding xsys_*)
CORE_SRCS:=$(filter-out xsys_%.c,$(wildcard *.c))
CORE_SRCSP:=$(filter-out xsys_%.cpp,$(wildcard *.cpp))

### generate a list of the mode-core sources
MODE_SRCS:=$(wildcard modes/*.c)

### generate lists of "all mode sources" and "each mode's sources"
MODE_MODE_SRCS:=
define mode_srcs
MODE_$1_SRCS:=$$(wildcard modes/$1/*.c)
MODE_MODE_SRCS+=$$(MODE_$1_SRCS)
endef
$(foreach mode,$(MODELIST),$(eval $(call mode_srcs,$(mode))))

### generate a list of the man directories
MAN_DIRS:=
define man_dirs
MAN_DIRS+=$$(filter $$(MANDIR)/man%,$1)
endef
$(foreach dir,$(wildcard $(MANDIR)/*),$(eval $(call man_dirs,$(dir))))

### generate a list of the man pages
SYS_MANPAGES:=
define man_srcs
SYS_MANPAGES+=$$(wildcard $(MANDIR)/man$(patsubst $(MANDIR)/man%,%,$1)/*.$(patsubst $(MANDIR)/man%,%,$1))
endef
$(foreach dir,$(MAN_DIRS),$(eval $(call man_srcs,$(dir))))
SYS_MANPAGES:=$(patsubst $(MANDIR)/%,%,$(SYS_MANPAGES))
ifneq ($(MAN2HTML),)
ifneq ($(shell which $(MAN2HTML)),)
SYS_HTMLPAGES:=$(addsuffix .html,$(SYS_MANPAGES))
endif
endif

### post
ifneq ($(POST_BUILD),)
-include $(POST_BUILD)
endif

### generate required object lists
CORE_OBJS:=$(addprefix $(BUILDDIR)/,$(CORE_SRCS:.c=$(OBJEXT)))
CORE_OBJSP:=$(addprefix $(BUILDDIR)/,$(CORE_SRCSP:.cpp=$(OBJEXT)))
MODE_OBJS:=$(addprefix $(BUILDDIR)/,$(subst /,_,$(MODE_SRCS:.c=$(OBJEXT))))
MODE_MODE_OBJS:=
define mode_objs
MODE_$1_OBJS:=$$(addprefix $$(BUILDDIR)/,$$(subst /,_,$$(MODE_$1_SRCS:.c=$(OBJEXT))))
MODE_MODE_OBJS+=$$(MODE_$1_OBJS)
endef
$(foreach mode,$(MODELIST),$(eval $(call mode_objs,$(mode))))

### make the dep files precious
.PRECIOUS: $(CORE_OBJS:$(OBJEXT)=$(DEPEXT))
.PRECIOUS: $(CORE_OBJSP:$(OBJEXT)=$(DEPEXT))
.PRECIOUS: $(MODE_OBJS:$(OBJEXT)=$(DEPEXT))
.PRECIOUS: $(MODE_MODE_OBJS:$(OBJEXT)=$(DEPEXT))

### make all of the objects depend on the config file
$(CORE_OBJS) $(CORE_OBJSP) $(MODE_OBJS) $(MODE_MODE_OBJS): config.mk

### reset the default goal
.DEFAULT_GOAL:=
