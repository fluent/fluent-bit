# Onigmo Makefile for Win32

product_name = onigmo

# Comment out the next line, if you don't want to use LTCG.
USE_LTCG = 1

# Comment out the next line, if you don't want to use multiprocess build.
USE_MP = 1

# Enable the next line, if you want to enable .pdb file on release build.
#ENABLE_PDB = 1

# Enable the next line, if you want to use a .def file.
#DEFFILE = onigmo.def


# Set ARCH. "x64" or "x86".
!ifndef ARCH
!if ("$(CPU)"=="AMD64" && !DEFINED(386)) || "$(TARGET_CPU)"=="x64" || DEFINED(AMD64) || "$(PLATFORM)"=="x64" || "$(PLATFORM)"=="X64"
ARCH = x64
!else
ARCH = x86
!endif
!endif


CPPFLAGS =
CFLAGS = -O2 -nologo -W3
LDFLAGS =
LOADLIBES =
ARLIB = lib
ARLIB_FLAGS = -nologo
ARDLL = cl
ARDLL_FLAGS = -nologo -LD $(LINKFLAGS) -dll
LINKFLAGS = -link -incremental:no

INSTALL = install -c
CP      = copy
RMDIR   = rd /s/q
CC = cl
RC = rc
DEFS = -DHAVE_CONFIG_H -DEXPORT

!if "$(ARCH)"=="x86"
PYTHON = py -3-32
!else
PYTHON = py -3
!endif

!ifdef DEBUG
DBGFLG = d
!else
DBGFLG =
!endif

WORKDIR = build_$(ARCH)$(DBGFLG)

# Get the version of cl.exe.
#  1. Write the version to a work file (mscver$(_NMAKE_VER).~).
!if ![(echo _MSC_VER>mscver$(_NMAKE_VER).c) && \
	(for /f %I in ('"$(CC) /EP mscver$(_NMAKE_VER).c 2>nul"') do @echo _MSC_VER=%I> mscver$(_NMAKE_VER).~)]
#  2. Include it.
!include mscver$(_NMAKE_VER).~
#  3. Clean up.
!if [del mscver$(_NMAKE_VER).~ mscver$(_NMAKE_VER).c]
!endif
!endif

!if DEFINED(USE_MP) && $(_MSC_VER) >= 1600
# Enable multiprocess build on VC2010+.
CFLAGS = $(CFLAGS) -MP
!endif

!ifdef DEBUG

# Debug Build

# Enable debug information.
CFLAGS = $(CFLAGS) -Zi -DDEBUG=1 -D_DEBUG=1 -MTd
# Debug flags. (see regint.h)
#CFLAGS = $(CFLAGS) -DONIG_DEBUG_PARSE_TREE -DONIG_DEBUG_COMPILE -DONIG_DEBUG_SEARCH -DONIG_DEBUG_MATCH -DONIG_DONT_OPTIMIZE
ARDLL_FLAGS = -MTd $(ARDLL_FLAGS) -debug

!else	# DEBUG

# Release Build

!if DEFINED(USE_LTCG) && $(_MSC_VER) >= 1300
# Use LTCG (Link Time Code Generation) on VC++ 7.0 or later.
CFLAGS = $(CFLAGS) -GL
ARLIB_FLAGS = $(ARLIB_FLAGS) -LTCG
ARDLL_FLAGS = $(ARDLL_FLAGS) -LTCG
!endif
!ifdef ENABLE_PDB
CFLAGS = $(CFLAGS) -Zi
ARDLL_FLAGS = $(ARDLL_FLAGS) -debug -PDBALTPATH:%%_PDB%%
!endif

!endif	# DEBUG

!ifdef DEFFILE
# Use a .def file to export APIs.
CFLAGS = $(CFLAGS) -DONIG_EXTERN=extern
ARDLL_FLAGS = $(ARDLL_FLAGS) -def:$(DEFFILE)
!endif

subdirs =

libbase   = onigmo
libname   = $(WORKDIR)\$(libbase)_s.lib
dllname   = $(WORKDIR)\$(libbase).dll
dlllib    = $(WORKDIR)\$(libbase).lib

onigheaders  = onigmo.h regint.h regparse.h regenc.h st.h
posixheaders = onigmoposix.h
headers      = $(posixheaders) $(onigheaders)

onigobjs      = $(WORKDIR)\reggnu.obj $(WORKDIR)\regerror.obj \
		$(WORKDIR)\regparse.obj $(WORKDIR)\regext.obj \
		$(WORKDIR)\regcomp.obj $(WORKDIR)\regexec.obj \
		$(WORKDIR)\regenc.obj $(WORKDIR)\regsyntax.obj \
		$(WORKDIR)\regtrav.obj $(WORKDIR)\regversion.obj \
		$(WORKDIR)\st.obj
posixobjs     = $(WORKDIR)\regposix.obj $(WORKDIR)\regposerr.obj
libobjs       = $(onigobjs) $(posixobjs)

jp_objs       = $(WORKDIR)\euc_jp.obj $(WORKDIR)\shift_jis.obj \
		$(WORKDIR)\windows_31j.obj

iso_8859_objs = $(WORKDIR)\iso_8859_1.obj  $(WORKDIR)\iso_8859_2.obj \
		$(WORKDIR)\iso_8859_3.obj  $(WORKDIR)\iso_8859_4.obj \
		$(WORKDIR)\iso_8859_5.obj  $(WORKDIR)\iso_8859_6.obj \
		$(WORKDIR)\iso_8859_7.obj  $(WORKDIR)\iso_8859_8.obj \
		$(WORKDIR)\iso_8859_9.obj  $(WORKDIR)\iso_8859_10.obj \
		$(WORKDIR)\iso_8859_11.obj $(WORKDIR)\iso_8859_13.obj \
		$(WORKDIR)\iso_8859_14.obj $(WORKDIR)\iso_8859_15.obj \
		$(WORKDIR)\iso_8859_16.obj

encobjs       = $(WORKDIR)\ascii.obj $(WORKDIR)\utf_8.obj \
		$(WORKDIR)\unicode.obj \
		$(WORKDIR)\utf_16be.obj $(WORKDIR)\utf_16le.obj \
		$(WORKDIR)\utf_32be.obj $(WORKDIR)\utf_32le.obj \
		$(jp_objs) $(iso_8859_objs) \
		$(WORKDIR)\euc_tw.obj $(WORKDIR)\euc_kr.obj $(WORKDIR)\big5.obj \
		$(WORKDIR)\gb18030.obj \
		$(WORKDIR)\koi8_r.obj $(WORKDIR)\koi8_u.obj \
		$(WORKDIR)\windows_1250.obj $(WORKDIR)\windows_1251.obj \
		$(WORKDIR)\windows_1252.obj $(WORKDIR)\windows_1253.obj \
		$(WORKDIR)\windows_1254.obj $(WORKDIR)\windows_1257.obj

resobj        = $(WORKDIR)\onigmo.res

onigsources  = regerror.c regparse.c regext.c regcomp.c regexec.c regenc.c \
	       regsyntax.c regtrav.c regversion.c reggnu.c st.c
posixsources = regposix.c regposerr.c
libsources   = $(posixsources) $(onigsources)

encdir       = enc
distfiles    = README COPYING HISTORY \
		Makefile.in configure.in config.h.in configure \
		$(headers) $(libsources) \
		test.rb testconv.rb
testc        = testc
testcu       = testu
testp        = testp

makeargs = $(MFLAGS) CPPFLAGS='$(CPPFLAGS)' CFLAGS='$(CFLAGS)' CC='$(CC)'

.SUFFIXES:
.SUFFIXES: .obj .c .h .ps .dvi .info .texinfo .res .rc

!ifdef NOBatch
.c{$(WORKDIR)\}.obj:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) /Iwin32 /I. /I.. /I$(encdir)\unicode /Fo$@ /c $<
!else
# batch-mode inference rules
.c{$(WORKDIR)\}.obj::
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) /Iwin32 /I. /Fo$(WORKDIR)\ /c $<
{$(encdir)\}.c{$(WORKDIR)\}.obj::
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) /Iwin32 /I. /I$(encdir)\unicode /Fo$(WORKDIR)\ /c $<
!endif

{win32\}.rc{$(WORKDIR)}.res:
	$(RC) /Fo$@ $<

# targets
default: all

setup:


all: lib dll

lib: $(libname)
dll: $(dllname)

$(libname): $(WORKDIR) $(libobjs) $(encobjs)
	$(ARLIB) $(ARLIB_FLAGS) -out:$@ $(libobjs) $(encobjs)

$(dllname): $(WORKDIR) $(libobjs) $(encobjs) $(resobj) $(DEFFILE)
	$(ARDLL) $(libobjs) $(encobjs) $(resobj) -Fe$@ $(ARDLL_FLAGS)

$(WORKDIR):
	-mkdir $(WORKDIR)

$(WORKDIR)\regparse.obj:  regparse.c $(onigheaders) win32\config.h st.h
$(WORKDIR)\regext.obj:    regext.c   $(onigheaders) win32\config.h
$(WORKDIR)\regtrav.obj:   regtrav.c  $(onigheaders) win32\config.h
$(WORKDIR)\regcomp.obj:   regcomp.c  $(onigheaders) win32\config.h
$(WORKDIR)\regexec.obj:   regexec.c  regint.h regenc.h onigmo.h win32\config.h
$(WORKDIR)\reggnu.obj:    reggnu.c   regint.h regenc.h onigmo.h win32\config.h onigmognu.h
$(WORKDIR)\regerror.obj:  regerror.c regint.h regenc.h onigmo.h win32\config.h
$(WORKDIR)\regenc.obj:    regenc.c   regint.h regenc.h onigmo.h win32\config.h
$(WORKDIR)\regsyntax.obj: regsyntax.c regint.h regenc.h onigmo.h win32\config.h
$(WORKDIR)\regversion.obj: regversion.c onigmo.h win32\config.h
$(WORKDIR)\regposix.obj:  regposix.c $(posixheaders) onigmo.h win32\config.h
$(WORKDIR)\regposerr.obj: regposerr.c $(posixheaders) win32\config.h
$(WORKDIR)\st.obj:        st.c regint.h onigmo.h win32\config.h st.h

$(WORKDIR)\ascii.obj:      $(encdir)\ascii.c regenc.h win32\config.h
$(WORKDIR)\unicode.obj:    $(encdir)\unicode.c regint.h regenc.h win32\config.h $(encdir)\unicode\casefold.h $(encdir)\unicode\name2ctype.h
$(WORKDIR)\utf_8.obj:      $(encdir)\utf_8.c regenc.h win32\config.h
$(WORKDIR)\utf_16be.obj:   $(encdir)\utf_16be.c regenc.h win32\config.h
$(WORKDIR)\utf_16le.obj:   $(encdir)\utf_16le.c regenc.h win32\config.h
$(WORKDIR)\utf_32be.obj:   $(encdir)\utf_32be.c regenc.h win32\config.h
$(WORKDIR)\utf_32le.obj:   $(encdir)\utf_32le.c regenc.h win32\config.h
$(WORKDIR)\euc_jp.obj:     $(encdir)\euc_jp.c regenc.h win32\config.h $(encdir)\jis\props.h
$(WORKDIR)\euc_tw.obj:     $(encdir)\euc_tw.c regenc.h win32\config.h
$(WORKDIR)\euc_kr.obj:     $(encdir)\euc_kr.c regenc.h win32\config.h
$(WORKDIR)\shift_jis.obj:  $(encdir)\shift_jis.c $(encdir)\shift_jis.h regenc.h win32\config.h $(encdir)\jis\props.h
$(WORKDIR)\windows_31j.obj: $(encdir)\windows_31j.c $(encdir)\shift_jis.h regenc.h win32\config.h $(encdir)\jis\props.h
$(WORKDIR)\iso_8859_1.obj:  $(encdir)\iso_8859_1.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_2.obj:  $(encdir)\iso_8859_2.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_3.obj:  $(encdir)\iso_8859_3.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_4.obj:  $(encdir)\iso_8859_4.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_5.obj:  $(encdir)\iso_8859_5.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_6.obj:  $(encdir)\iso_8859_6.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_7.obj:  $(encdir)\iso_8859_7.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_8.obj:  $(encdir)\iso_8859_8.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_9.obj:  $(encdir)\iso_8859_9.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_10.obj: $(encdir)\iso_8859_10.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_11.obj: $(encdir)\iso_8859_11.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_13.obj: $(encdir)\iso_8859_13.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_14.obj: $(encdir)\iso_8859_14.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_15.obj: $(encdir)\iso_8859_15.c regenc.h win32\config.h
$(WORKDIR)\iso_8859_16.obj: $(encdir)\iso_8859_16.c regenc.h win32\config.h
#$(WORKDIR)\koi8.obj:       $(encdir)\koi8.c   regenc.h win32\config.h
$(WORKDIR)\koi8_r.obj:     $(encdir)\koi8_r.c regenc.h win32\config.h
$(WORKDIR)\koi8_u.obj:     $(encdir)\koi8_u.c regenc.h win32\config.h
$(WORKDIR)\windows_1250.obj: $(encdir)\windows_1250.c regenc.h win32\config.h
$(WORKDIR)\windows_1251.obj: $(encdir)\windows_1251.c regenc.h win32\config.h
$(WORKDIR)\windows_1252.obj: $(encdir)\windows_1252.c regenc.h win32\config.h
$(WORKDIR)\windows_1253.obj: $(encdir)\windows_1253.c regenc.h win32\config.h
$(WORKDIR)\windows_1254.obj: $(encdir)\windows_1254.c regenc.h win32\config.h
$(WORKDIR)\windows_1257.obj: $(encdir)\windows_1257.c regenc.h win32\config.h
$(WORKDIR)\big5.obj:       $(encdir)\big5.c   regenc.h win32\config.h
$(WORKDIR)\gb18030.obj:    $(encdir)\gb18030.c   regenc.h win32\config.h

$(WORKDIR)\onigmo.res: win32\onigmo.rc onigmo.h


# Tests
test: all ctest utest ptest pytest

# C library test
ctest: $(WORKDIR)\$(testc).exe
	$(WORKDIR)\$(testc)

# C library test (Unicode)
utest: $(WORKDIR)\$(testcu).exe
	$(WORKDIR)\$(testcu)

# POSIX C library test
ptest: $(WORKDIR)\$(testp).exe
	$(WORKDIR)\$(testp)

# Python test
pytest:
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py EUC-JP
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py SJIS
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py UTF-8
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py UTF-16LE
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py UTF-16BE
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py UTF-32LE
	cd $(WORKDIR) && $(PYTHON) ..\testpy.py UTF-32BE


$(WORKDIR)\$(testc).exe: win32\$(testc).c $(libname)
	$(CC) $(CFLAGS) -Fe$(WORKDIR)\$(testc) -DONIG_EXTERN=extern win32\$(testc).c -I. $(libname)

$(WORKDIR)\$(testp).exe: win32\$(testc).c $(dlllib)
	$(CC) $(CFLAGS) -DPOSIX_TEST -Fe$(WORKDIR)\$(testp) win32\$(testc).c -I. $(dlllib)

#$(testc)u.c: test.rb testconvu.rb
#	ruby -Ke testconvu.rb test.rb > $@

$(WORKDIR)\$(testcu).exe: $(testcu).c $(libname)
	$(CC) $(CFLAGS) -Fe$(WORKDIR)\$(testcu) -DONIG_EXTERN=extern $(testcu).c -I. $(libname)

$(libbase).def: win32\makedef.py onigmo.h regenc.h onigmognu.h onigmoposix.h
	$(PYTHON) win32\makedef.py > $@

clean:
	-$(RMDIR) $(WORKDIR)


samples: all
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Fesimple  ..\sample\simple.c  ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Feposix   ..\sample\posix.c   ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Fenames   ..\sample\names.c   ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Felistcap ..\sample\listcap.c ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Fesql     ..\sample\sql.c     ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Feencode  ..\sample\encode.c  ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Fesyntax  ..\sample\syntax.c  ..\$(dlllib)
	cd $(WORKDIR) && $(CC) $(CFLAGS) -I.. -Fecrnl    ..\sample\crnl.c    ..\$(dlllib)
