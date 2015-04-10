DEFCONFIG:=            darwin.mk
BUILD_RULES:=          darwin.mk
INSTALL_RULES:=        darwin.mk

AS=                    $(CROSS_COMPILE)as
GCC=                   $(CROSS_COMPILE)gcc
GXX=                   $(CROSS_COMPILE)g++
LD=                    $(CROSS_COMPILE)ld
OBJCOPY=               $(CROSS_COMPILE)objcopy
AR=                    $(CROSS_COMPILE)ar
DEFLATE:=              gzip
SYMLINK:=              ln
MKDIR=                 @if [ ! -d $* ]; then echo "mkdir -p $*"; mkdir -p $*; else echo "!mkdir $*"; fi
RM:=                   rm -f
RMDIR:=                rm -rf
INSTALL=               install -g $(SYS_GROUP) -o $(SYS_USER)
MAN2HTML:=             man2html

DEBUG:=                -g
LIBS:=                 pthread
CFLAGS+=               -Wall -c -fPIC $(DEBUG) $(addprefix -D,$(OPTIONS))
#CFLAGS+=              -pedantic
#CFLAGS+=               -fvisibility=hidden
CFLAGS+=               -Wno-variadic-macros
CXXFLAGS:=             $(CFLAGS) -fvisibility=hidden
CFLAGS+=               -Wstrict-prototypes
CLINKS+=               -fPIC $(addprefix -l,$(LIBS)) $(DEBUG)
CXXLINKS+=             $(CLINKS)

LIB_OUT=               $(DESTDIR)/$(LIBNAME).dylib                    \
                       $(DESTDIR)/$(LIBNAME).a                     \
                       $(addprefix $(HTMLDIR)/,$(SYS_HTMLPAGES))

#                       $(DESTDIR)/$(LIBNAME)p.dylib                   \
#                       $(DESTDIR)/$(LIBNAME)p.a                    \

INSTALL_FILES=         $(SYS_LIBDIR)/$(LIBNAME).dylib.$(LIBFULLREV)                    \
                       $(SYS_LIBDIR)/$(LIBNAME).dylib                                  \
                       $(SYS_LIBDIR)/$(LIBNAME).a.$(LIBFULLREV)                     \
                       $(SYS_LIBDIR)/$(LIBNAME).a                                   \
                       $(addprefix $(SYS_MANDIR)/,$(addsuffix .gz,$(SYS_MANPAGES))) \
                       $(SYS_INCDIR)/xbee.h

#                       $(SYS_LIBDIR)/$(LIBNAME)p.dylib.$(LIBFULLREV)                   \
#                       $(SYS_LIBDIR)/$(LIBNAME)p.dylib                                 \
#                       $(SYS_LIBDIR)/$(LIBNAME)p.a.$(LIBFULLREV)                    \
#                       $(SYS_LIBDIR)/$(LIBNAME)p.a                                  \
#                       $(SYS_INCDIR)/xbeep.h

RELEASE_FILES=         $(DESTDIR)/$(LIBNAME).dylib.$(LIBFULLREV)      \
                       $(DESTDIR)/$(LIBNAME).dylib                    \
                       $(DESTDIR)/$(LIBNAME).a.$(LIBFULLREV)       \
                       $(DESTDIR)/$(LIBNAME).a                     \
                       $(addprefix $(MANDIR)/,$(SYS_MANPAGES))     \
                       $(addprefix $(HTMLDIR)/,$(SYS_HTMLPAGES))   \
                       xbee.h                                      \
                       README HISTORY COPYING COPYING.LESSER
#                       $(DESTDIR)/$(LIBNAME)p.dylib.$(LIBFULLREV)     \
#                       $(DESTDIR)/$(LIBNAME)p.dylib                   \
#                       $(DESTDIR)/$(LIBNAME)p.a.$(LIBFULLREV)      \
#                       $(DESTDIR)/$(LIBNAME)p.a                    \
#                       xbeep.h                                     \

CLEAN_FILES=           $(BUILDDIR)/*.o \
                       $(BUILDDIR)/*.d

DISTCLEAN_FILES=       $(HTMLDIR)/*/*.html

VER_DEFINES=           -DLIB_REVISION="\"$(LIBFULLREV)\""                             \
                       -DLIB_COMMIT="\"$(shell git log -1 --format="%H")\""           \
                       -DLIB_COMMITTER="\"$(shell git log -1 --format="%cn <%ce>")\"" \
                       -DLIB_BUILDTIME="\"$(shell date)\""
