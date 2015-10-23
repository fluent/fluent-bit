lib_LTLIBRARIES = libmsgpack.la

AM_CPPFLAGS = -I../include

libmsgpack_la_SOURCES = \
		unpack.c \
		objectc.c \
		version.c \
		vrefbuffer.c \
		zone.c

if ENABLE_GCC_CXX_ATOMIC
	CXXFLAGS="$CXXFLAGS -DENABLE_GCC_CXX_ATOMIC"
endif


# -version-info CURRENT:REVISION:AGE
libmsgpack_la_LDFLAGS = -version-info 4:0:0 -no-undefined


# backward compatibility
lib_LTLIBRARIES += libmsgpackc.la

libmsgpackc_la_SOURCES = \
		unpack.c \
		objectc.c \
		version.c \
		vrefbuffer.c \
		zone.c

libmsgpackc_la_LDFLAGS = -version-info 2:0:0 -no-undefined


nobase_include_HEADERS = \
		../include/msgpack/pack_define.h \
		../include/msgpack/pack_template.h \
		../include/msgpack/unpack_define.h \
		../include/msgpack/unpack_template.h \
		../include/msgpack/util.h \
		../include/msgpack/sysdep.h \
		../include/msgpack/gcc_atomic.h \
		../include/msgpack.h \
		../include/msgpack/sbuffer.h \
		../include/msgpack/version.h \
		../include/msgpack/version_master.h \
		../include/msgpack/vrefbuffer.h \
		../include/msgpack/zbuffer.h \
		../include/msgpack/fbuffer.h \
		../include/msgpack/pack.h \
		../include/msgpack/unpack.h \
		../include/msgpack/object.h \
		../include/msgpack/zone.h

nobase_include_HEADERS += \
		../include/msgpack/predef.h \
		../include/msgpack/predef/make.h \
		../include/msgpack/predef/platform.h \
		../include/msgpack/predef/other.h \
		../include/msgpack/predef/platform/windows_phone.h \
		../include/msgpack/predef/platform/windows_desktop.h \
		../include/msgpack/predef/platform/mingw.h \
		../include/msgpack/predef/platform/windows_store.h \
		../include/msgpack/predef/platform/windows_runtime.h \
		../include/msgpack/predef/architecture/x86.h \
		../include/msgpack/predef/architecture/arm.h \
		../include/msgpack/predef/architecture/convex.h \
		../include/msgpack/predef/architecture/parisc.h \
		../include/msgpack/predef/architecture/sys390.h \
		../include/msgpack/predef/architecture/x86/32.h \
		../include/msgpack/predef/architecture/x86/64.h \
		../include/msgpack/predef/architecture/m68k.h \
		../include/msgpack/predef/architecture/sys370.h \
		../include/msgpack/predef/architecture/rs6k.h \
		../include/msgpack/predef/architecture/mips.h \
		../include/msgpack/predef/architecture/pyramid.h \
		../include/msgpack/predef/architecture/alpha.h \
		../include/msgpack/predef/architecture/superh.h \
		../include/msgpack/predef/architecture/z.h \
		../include/msgpack/predef/architecture/blackfin.h \
		../include/msgpack/predef/architecture/sparc.h \
		../include/msgpack/predef/architecture/ppc.h \
		../include/msgpack/predef/architecture/ia64.h \
		../include/msgpack/predef/other/endian.h \
		../include/msgpack/predef/language/objc.h \
		../include/msgpack/predef/language/stdcpp.h \
		../include/msgpack/predef/language/stdc.h \
		../include/msgpack/predef/detail/endian_compat.h \
		../include/msgpack/predef/detail/comp_detected.h \
		../include/msgpack/predef/detail/platform_detected.h \
		../include/msgpack/predef/detail/os_detected.h \
		../include/msgpack/predef/detail/test.h \
		../include/msgpack/predef/detail/_exception.h \
		../include/msgpack/predef/detail/_cassert.h \
		../include/msgpack/predef/version_number.h \
		../include/msgpack/predef/compiler.h \
		../include/msgpack/predef/compiler/borland.h \
		../include/msgpack/predef/compiler/kai.h \
		../include/msgpack/predef/compiler/hp_acc.h \
		../include/msgpack/predef/compiler/ibm.h \
		../include/msgpack/predef/compiler/sgi_mipspro.h \
		../include/msgpack/predef/compiler/digitalmars.h \
		../include/msgpack/predef/compiler/llvm.h \
		../include/msgpack/predef/compiler/sunpro.h \
		../include/msgpack/predef/compiler/watcom.h \
		../include/msgpack/predef/compiler/comeau.h \
		../include/msgpack/predef/compiler/edg.h \
		../include/msgpack/predef/compiler/pgi.h \
		../include/msgpack/predef/compiler/microtec.h \
		../include/msgpack/predef/compiler/metaware.h \
		../include/msgpack/predef/compiler/palm.h \
		../include/msgpack/predef/compiler/iar.h \
		../include/msgpack/predef/compiler/intel.h \
		../include/msgpack/predef/compiler/clang.h \
		../include/msgpack/predef/compiler/visualc.h \
		../include/msgpack/predef/compiler/ekopath.h \
		../include/msgpack/predef/compiler/gcc_xml.h \
		../include/msgpack/predef/compiler/compaq.h \
		../include/msgpack/predef/compiler/dignus.h \
		../include/msgpack/predef/compiler/tendra.h \
		../include/msgpack/predef/compiler/greenhills.h \
		../include/msgpack/predef/compiler/mpw.h \
		../include/msgpack/predef/compiler/metrowerks.h \
		../include/msgpack/predef/compiler/diab.h \
		../include/msgpack/predef/compiler/gcc.h \
		../include/msgpack/predef/os/unix.h \
		../include/msgpack/predef/os/bsd.h \
		../include/msgpack/predef/os/solaris.h \
		../include/msgpack/predef/os/windows.h \
		../include/msgpack/predef/os/hpux.h \
		../include/msgpack/predef/os/macos.h \
		../include/msgpack/predef/os/os400.h \
		../include/msgpack/predef/os/beos.h \
		../include/msgpack/predef/os/aix.h \
		../include/msgpack/predef/os/bsd/dragonfly.h \
		../include/msgpack/predef/os/bsd/net.h \
		../include/msgpack/predef/os/bsd/free.h \
		../include/msgpack/predef/os/bsd/bsdi.h \
		../include/msgpack/predef/os/bsd/open.h \
		../include/msgpack/predef/os/cygwin.h \
		../include/msgpack/predef/os/irix.h \
		../include/msgpack/predef/os/ios.h \
		../include/msgpack/predef/os/amigaos.h \
		../include/msgpack/predef/os/vms.h \
		../include/msgpack/predef/os/linux.h \
		../include/msgpack/predef/os/qnxnto.h \
		../include/msgpack/predef/os/haiku.h \
		../include/msgpack/predef/os/android.h \
		../include/msgpack/predef/architecture.h \
		../include/msgpack/predef/os.h \
		../include/msgpack/predef/library.h \
		../include/msgpack/predef/version.h \
		../include/msgpack/predef/language.h \
		../include/msgpack/predef/library/c/_prefix.h \
		../include/msgpack/predef/library/c/uc.h \
		../include/msgpack/predef/library/c/gnu.h \
		../include/msgpack/predef/library/c/vms.h \
		../include/msgpack/predef/library/c/zos.h \
		../include/msgpack/predef/library/c.h \
		../include/msgpack/predef/library/std/_prefix.h \
		../include/msgpack/predef/library/std/cxx.h \
		../include/msgpack/predef/library/std/sgi.h \
		../include/msgpack/predef/library/std/libcomo.h \
		../include/msgpack/predef/library/std/stdcpp3.h \
		../include/msgpack/predef/library/std/vacpp.h \
		../include/msgpack/predef/library/std/stlport.h \
		../include/msgpack/predef/library/std/dinkumware.h \
		../include/msgpack/predef/library/std/msl.h \
		../include/msgpack/predef/library/std/roguewave.h \
		../include/msgpack/predef/library/std/modena.h \
		../include/msgpack/predef/library/std.h

if ENABLE_CXX
nobase_include_HEADERS += \
		../include/msgpack.hpp \
		../include/msgpack/adaptor/adaptor_base.hpp \
		../include/msgpack/adaptor/array_ref.hpp \
		../include/msgpack/adaptor/bool.hpp \
		../include/msgpack/adaptor/boost/fusion.hpp \
		../include/msgpack/adaptor/boost/msgpack_variant.hpp \
		../include/msgpack/adaptor/boost/optional.hpp \
		../include/msgpack/adaptor/boost/string_ref.hpp \
		../include/msgpack/adaptor/char_ptr.hpp \
		../include/msgpack/adaptor/check_container_size.hpp \
		../include/msgpack/adaptor/cpp11/array.hpp \
		../include/msgpack/adaptor/cpp11/array_char.hpp \
		../include/msgpack/adaptor/cpp11/array_unsigned_char.hpp \
		../include/msgpack/adaptor/cpp11/forward_list.hpp \
		../include/msgpack/adaptor/cpp11/shared_ptr.hpp \
		../include/msgpack/adaptor/cpp11/tuple.hpp \
		../include/msgpack/adaptor/cpp11/unique_ptr.hpp \
		../include/msgpack/adaptor/cpp11/unordered_map.hpp \
		../include/msgpack/adaptor/cpp11/unordered_set.hpp \
		../include/msgpack/adaptor/define.hpp \
		../include/msgpack/adaptor/deque.hpp \
		../include/msgpack/adaptor/detail/cpp03_define_map.hpp \
		../include/msgpack/adaptor/detail/cpp03_define_array.hpp \
		../include/msgpack/adaptor/detail/cpp03_msgpack_tuple.hpp \
		../include/msgpack/adaptor/detail/cpp11_define_array.hpp \
		../include/msgpack/adaptor/detail/cpp11_define_map.hpp \
		../include/msgpack/adaptor/detail/cpp11_msgpack_tuple.hpp \
		../include/msgpack/adaptor/ext.hpp \
		../include/msgpack/adaptor/fixint.hpp \
		../include/msgpack/adaptor/float.hpp \
		../include/msgpack/adaptor/int.hpp \
		../include/msgpack/adaptor/list.hpp \
		../include/msgpack/adaptor/map.hpp \
		../include/msgpack/adaptor/msgpack_tuple.hpp \
		../include/msgpack/adaptor/nil.hpp \
		../include/msgpack/adaptor/pair.hpp \
		../include/msgpack/adaptor/raw.hpp \
		../include/msgpack/adaptor/v4raw.hpp \
		../include/msgpack/adaptor/set.hpp \
		../include/msgpack/adaptor/string.hpp \
		../include/msgpack/adaptor/tr1/unordered_map.hpp \
		../include/msgpack/adaptor/tr1/unordered_set.hpp \
		../include/msgpack/adaptor/vector.hpp \
		../include/msgpack/adaptor/vector_bool.hpp \
		../include/msgpack/adaptor/vector_char.hpp \
		../include/msgpack/adaptor/vector_unsigned_char.hpp \
		../include/msgpack/cpp_config.hpp \
		../include/msgpack/detail/cpp03_zone.hpp \
		../include/msgpack/detail/cpp11_zone.hpp \
		../include/msgpack/fbuffer.hpp \
		../include/msgpack/iterator.hpp \
		../include/msgpack/meta.hpp \
		../include/msgpack/object.hpp \
		../include/msgpack/object_fwd.hpp \
		../include/msgpack/pack.hpp \
		../include/msgpack/sbuffer.hpp \
		../include/msgpack/type.hpp \
		../include/msgpack/unpack.hpp \
		../include/msgpack/version.hpp \
		../include/msgpack/versioning.hpp \
		../include/msgpack/vrefbuffer.hpp \
		../include/msgpack/zbuffer.hpp \
		../include/msgpack/zone.hpp

nobase_include_HEADERS += \
		../include/msgpack/preprocessor.hpp \
		../include/msgpack/preprocessor/dec.hpp \
		../include/msgpack/preprocessor/slot.hpp \
		../include/msgpack/preprocessor/wstringize.hpp \
		../include/msgpack/preprocessor/enum_params_with_defaults.hpp \
		../include/msgpack/preprocessor/enum.hpp \
		../include/msgpack/preprocessor/facilities.hpp \
		../include/msgpack/preprocessor/enum_params_with_a_default.hpp \
		../include/msgpack/preprocessor/assert_msg.hpp \
		../include/msgpack/preprocessor/if.hpp \
		../include/msgpack/preprocessor/variadic.hpp \
		../include/msgpack/preprocessor/tuple.hpp \
		../include/msgpack/preprocessor/comma_if.hpp \
		../include/msgpack/preprocessor/identity.hpp \
		../include/msgpack/preprocessor/repeat_from_to.hpp \
		../include/msgpack/preprocessor/arithmetic/dec.hpp \
		../include/msgpack/preprocessor/arithmetic/mod.hpp \
		../include/msgpack/preprocessor/arithmetic/inc.hpp \
		../include/msgpack/preprocessor/arithmetic/mul.hpp \
		../include/msgpack/preprocessor/arithmetic/detail/div_base.hpp \
		../include/msgpack/preprocessor/arithmetic/div.hpp \
		../include/msgpack/preprocessor/arithmetic/sub.hpp \
		../include/msgpack/preprocessor/arithmetic/add.hpp \
		../include/msgpack/preprocessor/selection.hpp \
		../include/msgpack/preprocessor/stringize.hpp \
		../include/msgpack/preprocessor/seq/enum.hpp \
		../include/msgpack/preprocessor/seq/pop_back.hpp \
		../include/msgpack/preprocessor/seq/elem.hpp \
		../include/msgpack/preprocessor/seq/subseq.hpp \
		../include/msgpack/preprocessor/seq/to_tuple.hpp \
		../include/msgpack/preprocessor/seq/for_each_i.hpp \
		../include/msgpack/preprocessor/seq/to_list.hpp \
		../include/msgpack/preprocessor/seq/size.hpp \
		../include/msgpack/preprocessor/seq/replace.hpp \
		../include/msgpack/preprocessor/seq/push_front.hpp \
		../include/msgpack/preprocessor/seq/variadic_seq_to_seq.hpp \
		../include/msgpack/preprocessor/seq/to_array.hpp \
		../include/msgpack/preprocessor/seq/seq.hpp \
		../include/msgpack/preprocessor/seq/fold_left.hpp \
		../include/msgpack/preprocessor/seq/detail/split.hpp \
		../include/msgpack/preprocessor/seq/detail/binary_transform.hpp \
		../include/msgpack/preprocessor/seq/push_back.hpp \
		../include/msgpack/preprocessor/seq/first_n.hpp \
		../include/msgpack/preprocessor/seq/for_each.hpp \
		../include/msgpack/preprocessor/seq/pop_front.hpp \
		../include/msgpack/preprocessor/seq/fold_right.hpp \
		../include/msgpack/preprocessor/seq/for_each_product.hpp \
		../include/msgpack/preprocessor/seq/insert.hpp \
		../include/msgpack/preprocessor/seq/cat.hpp \
		../include/msgpack/preprocessor/seq/rest_n.hpp \
		../include/msgpack/preprocessor/seq/remove.hpp \
		../include/msgpack/preprocessor/seq/transform.hpp \
		../include/msgpack/preprocessor/seq/reverse.hpp \
		../include/msgpack/preprocessor/seq/filter.hpp \
		../include/msgpack/preprocessor/max.hpp \
		../include/msgpack/preprocessor/repeat_from_to_2nd.hpp \
		../include/msgpack/preprocessor/repetition/enum_trailing_binary_params.hpp \
		../include/msgpack/preprocessor/repetition/enum_params_with_defaults.hpp \
		../include/msgpack/preprocessor/repetition/enum.hpp \
		../include/msgpack/preprocessor/repetition/enum_params_with_a_default.hpp \
		../include/msgpack/preprocessor/repetition/repeat_from_to.hpp \
		../include/msgpack/preprocessor/repetition/enum_binary_params.hpp \
		../include/msgpack/preprocessor/repetition/deduce_z.hpp \
		../include/msgpack/preprocessor/repetition/enum_shifted_params.hpp \
		../include/msgpack/preprocessor/repetition/enum_shifted.hpp \
		../include/msgpack/preprocessor/repetition/enum_params.hpp \
		../include/msgpack/preprocessor/repetition/enum_trailing.hpp \
		../include/msgpack/preprocessor/repetition/detail/msvc/for.hpp \
		../include/msgpack/preprocessor/repetition/detail/edg/for.hpp \
		../include/msgpack/preprocessor/repetition/detail/for.hpp \
		../include/msgpack/preprocessor/repetition/detail/dmc/for.hpp \
		../include/msgpack/preprocessor/repetition/repeat.hpp \
		../include/msgpack/preprocessor/repetition/deduce_r.hpp \
		../include/msgpack/preprocessor/repetition/for.hpp \
		../include/msgpack/preprocessor/repetition/enum_trailing_params.hpp \
		../include/msgpack/preprocessor/repetition/enum_shifted_binary_params.hpp \
		../include/msgpack/preprocessor/control/expr_iif.hpp \
		../include/msgpack/preprocessor/control/if.hpp \
		../include/msgpack/preprocessor/control/detail/msvc/while.hpp \
		../include/msgpack/preprocessor/control/detail/while.hpp \
		../include/msgpack/preprocessor/control/detail/edg/while.hpp \
		../include/msgpack/preprocessor/control/detail/dmc/while.hpp \
		../include/msgpack/preprocessor/control/iif.hpp \
		../include/msgpack/preprocessor/control/expr_if.hpp \
		../include/msgpack/preprocessor/control/while.hpp \
		../include/msgpack/preprocessor/control/deduce_d.hpp \
		../include/msgpack/preprocessor/control.hpp \
		../include/msgpack/preprocessor/iteration/detail/finish.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/lower3.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/upper2.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/lower1.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/upper4.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/lower4.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/lower2.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/lower5.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/upper1.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/upper5.hpp \
		../include/msgpack/preprocessor/iteration/detail/bounds/upper3.hpp \
		../include/msgpack/preprocessor/iteration/detail/start.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/reverse1.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/forward2.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/forward3.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/reverse4.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/reverse2.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/forward4.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/reverse5.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/forward5.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/reverse3.hpp \
		../include/msgpack/preprocessor/iteration/detail/iter/forward1.hpp \
		../include/msgpack/preprocessor/iteration/detail/rlocal.hpp \
		../include/msgpack/preprocessor/iteration/detail/local.hpp \
		../include/msgpack/preprocessor/iteration/detail/self.hpp \
		../include/msgpack/preprocessor/iteration/local.hpp \
		../include/msgpack/preprocessor/iteration/self.hpp \
		../include/msgpack/preprocessor/iteration/iterate.hpp \
		../include/msgpack/preprocessor/comparison.hpp \
		../include/msgpack/preprocessor/punctuation/comma_if.hpp \
		../include/msgpack/preprocessor/punctuation/paren_if.hpp \
		../include/msgpack/preprocessor/punctuation/is_begin_parens.hpp \
		../include/msgpack/preprocessor/punctuation/comma.hpp \
		../include/msgpack/preprocessor/punctuation/detail/is_begin_parens.hpp \
		../include/msgpack/preprocessor/punctuation/remove_parens.hpp \
		../include/msgpack/preprocessor/punctuation/paren.hpp \
		../include/msgpack/preprocessor/slot/slot.hpp \
		../include/msgpack/preprocessor/slot/detail/shared.hpp \
		../include/msgpack/preprocessor/slot/detail/slot1.hpp \
		../include/msgpack/preprocessor/slot/detail/slot2.hpp \
		../include/msgpack/preprocessor/slot/detail/slot3.hpp \
		../include/msgpack/preprocessor/slot/detail/def.hpp \
		../include/msgpack/preprocessor/slot/detail/counter.hpp \
		../include/msgpack/preprocessor/slot/detail/slot4.hpp \
		../include/msgpack/preprocessor/slot/detail/slot5.hpp \
		../include/msgpack/preprocessor/slot/counter.hpp \
		../include/msgpack/preprocessor/enum_shifted_params.hpp \
		../include/msgpack/preprocessor/config/config.hpp \
		../include/msgpack/preprocessor/config/limits.hpp \
		../include/msgpack/preprocessor/enum_shifted.hpp \
		../include/msgpack/preprocessor/enum_params.hpp \
		../include/msgpack/preprocessor/repeat_3rd.hpp \
		../include/msgpack/preprocessor/comma.hpp \
		../include/msgpack/preprocessor/seq.hpp \
		../include/msgpack/preprocessor/inc.hpp \
		../include/msgpack/preprocessor/debug/error.hpp \
		../include/msgpack/preprocessor/debug/assert.hpp \
		../include/msgpack/preprocessor/debug/line.hpp \
		../include/msgpack/preprocessor/selection/max.hpp \
		../include/msgpack/preprocessor/selection/min.hpp \
		../include/msgpack/preprocessor/detail/is_nullary.hpp \
		../include/msgpack/preprocessor/detail/check.hpp \
		../include/msgpack/preprocessor/detail/split.hpp \
		../include/msgpack/preprocessor/detail/null.hpp \
		../include/msgpack/preprocessor/detail/is_unary.hpp \
		../include/msgpack/preprocessor/detail/is_binary.hpp \
		../include/msgpack/preprocessor/detail/dmc/auto_rec.hpp \
		../include/msgpack/preprocessor/detail/auto_rec.hpp \
		../include/msgpack/preprocessor/punctuation.hpp \
		../include/msgpack/preprocessor/array/enum.hpp \
		../include/msgpack/preprocessor/array/pop_back.hpp \
		../include/msgpack/preprocessor/array/elem.hpp \
		../include/msgpack/preprocessor/array/data.hpp \
		../include/msgpack/preprocessor/array/to_tuple.hpp \
		../include/msgpack/preprocessor/array/to_list.hpp \
		../include/msgpack/preprocessor/array/size.hpp \
		../include/msgpack/preprocessor/array/replace.hpp \
		../include/msgpack/preprocessor/array/push_front.hpp \
		../include/msgpack/preprocessor/array/detail/get_data.hpp \
		../include/msgpack/preprocessor/array/to_seq.hpp \
		../include/msgpack/preprocessor/array/push_back.hpp \
		../include/msgpack/preprocessor/array/pop_front.hpp \
		../include/msgpack/preprocessor/array/insert.hpp \
		../include/msgpack/preprocessor/array/remove.hpp \
		../include/msgpack/preprocessor/array/reverse.hpp \
		../include/msgpack/preprocessor/logical.hpp \
		../include/msgpack/preprocessor/min.hpp \
		../include/msgpack/preprocessor/debug.hpp \
		../include/msgpack/preprocessor/repeat.hpp \
		../include/msgpack/preprocessor/expand.hpp \
		../include/msgpack/preprocessor/limits.hpp \
		../include/msgpack/preprocessor/expr_if.hpp \
		../include/msgpack/preprocessor/iteration.hpp \
		../include/msgpack/preprocessor/while.hpp \
		../include/msgpack/preprocessor/repetition.hpp \
		../include/msgpack/preprocessor/repeat_2nd.hpp \
		../include/msgpack/preprocessor/arithmetic.hpp \
		../include/msgpack/preprocessor/list/enum.hpp \
		../include/msgpack/preprocessor/list/to_tuple.hpp \
		../include/msgpack/preprocessor/list/for_each_i.hpp \
		../include/msgpack/preprocessor/list/size.hpp \
		../include/msgpack/preprocessor/list/to_array.hpp \
		../include/msgpack/preprocessor/list/fold_left.hpp \
		../include/msgpack/preprocessor/list/append.hpp \
		../include/msgpack/preprocessor/list/detail/fold_left.hpp \
		../include/msgpack/preprocessor/list/detail/edg/fold_left.hpp \
		../include/msgpack/preprocessor/list/detail/edg/fold_right.hpp \
		../include/msgpack/preprocessor/list/detail/fold_right.hpp \
		../include/msgpack/preprocessor/list/detail/dmc/fold_left.hpp \
		../include/msgpack/preprocessor/list/to_seq.hpp \
		../include/msgpack/preprocessor/list/first_n.hpp \
		../include/msgpack/preprocessor/list/for_each.hpp \
		../include/msgpack/preprocessor/list/at.hpp \
		../include/msgpack/preprocessor/list/fold_right.hpp \
		../include/msgpack/preprocessor/list/for_each_product.hpp \
		../include/msgpack/preprocessor/list/cat.hpp \
		../include/msgpack/preprocessor/list/rest_n.hpp \
		../include/msgpack/preprocessor/list/transform.hpp \
		../include/msgpack/preprocessor/list/adt.hpp \
		../include/msgpack/preprocessor/list/reverse.hpp \
		../include/msgpack/preprocessor/list/filter.hpp \
		../include/msgpack/preprocessor/comparison/less_equal.hpp \
		../include/msgpack/preprocessor/comparison/less.hpp \
		../include/msgpack/preprocessor/comparison/not_equal.hpp \
		../include/msgpack/preprocessor/comparison/equal.hpp \
		../include/msgpack/preprocessor/comparison/greater.hpp \
		../include/msgpack/preprocessor/comparison/greater_equal.hpp \
		../include/msgpack/preprocessor/repeat_from_to_3rd.hpp \
		../include/msgpack/preprocessor/array.hpp \
		../include/msgpack/preprocessor/variadic/elem.hpp \
		../include/msgpack/preprocessor/variadic/to_tuple.hpp \
		../include/msgpack/preprocessor/variadic/to_list.hpp \
		../include/msgpack/preprocessor/variadic/size.hpp \
		../include/msgpack/preprocessor/variadic/to_array.hpp \
		../include/msgpack/preprocessor/variadic/detail/is_single_return.hpp \
		../include/msgpack/preprocessor/variadic/to_seq.hpp \
		../include/msgpack/preprocessor/cat.hpp \
		../include/msgpack/preprocessor/for.hpp \
		../include/msgpack/preprocessor/tuple/enum.hpp \
		../include/msgpack/preprocessor/tuple/pop_back.hpp \
		../include/msgpack/preprocessor/tuple/elem.hpp \
		../include/msgpack/preprocessor/tuple/to_list.hpp \
		../include/msgpack/preprocessor/tuple/size.hpp \
		../include/msgpack/preprocessor/tuple/replace.hpp \
		../include/msgpack/preprocessor/tuple/rem.hpp \
		../include/msgpack/preprocessor/tuple/push_front.hpp \
		../include/msgpack/preprocessor/tuple/to_array.hpp \
		../include/msgpack/preprocessor/tuple/detail/is_single_return.hpp \
		../include/msgpack/preprocessor/tuple/to_seq.hpp \
		../include/msgpack/preprocessor/tuple/push_back.hpp \
		../include/msgpack/preprocessor/tuple/pop_front.hpp \
		../include/msgpack/preprocessor/tuple/insert.hpp \
		../include/msgpack/preprocessor/tuple/remove.hpp \
		../include/msgpack/preprocessor/tuple/eat.hpp \
		../include/msgpack/preprocessor/tuple/reverse.hpp \
		../include/msgpack/preprocessor/list.hpp \
		../include/msgpack/preprocessor/logical/bool.hpp \
		../include/msgpack/preprocessor/logical/or.hpp \
		../include/msgpack/preprocessor/logical/compl.hpp \
		../include/msgpack/preprocessor/logical/xor.hpp \
		../include/msgpack/preprocessor/logical/bitnor.hpp \
		../include/msgpack/preprocessor/logical/nor.hpp \
		../include/msgpack/preprocessor/logical/not.hpp \
		../include/msgpack/preprocessor/logical/bitor.hpp \
		../include/msgpack/preprocessor/logical/bitxor.hpp \
		../include/msgpack/preprocessor/logical/and.hpp \
		../include/msgpack/preprocessor/logical/bitand.hpp \
		../include/msgpack/preprocessor/empty.hpp \
		../include/msgpack/preprocessor/library.hpp \
		../include/msgpack/preprocessor/facilities/identity.hpp \
		../include/msgpack/preprocessor/facilities/is_empty.hpp \
		../include/msgpack/preprocessor/facilities/apply.hpp \
		../include/msgpack/preprocessor/facilities/is_empty_variadic.hpp \
		../include/msgpack/preprocessor/facilities/is_empty_or_1.hpp \
		../include/msgpack/preprocessor/facilities/intercept.hpp \
		../include/msgpack/preprocessor/facilities/detail/is_empty.hpp \
		../include/msgpack/preprocessor/facilities/expand.hpp \
		../include/msgpack/preprocessor/facilities/overload.hpp \
		../include/msgpack/preprocessor/facilities/is_1.hpp \
		../include/msgpack/preprocessor/facilities/empty.hpp \
		../include/msgpack/preprocessor/iterate.hpp
endif

EXTRA_DIST = \
		../erb/cpp03_zone.hpp.erb \
		../erb/cpp03_define_array.hpp.erb \
		../erb/cpp03_define_map.hpp.erb \
		../erb/cpp03_msgpack_tuple.hpp.erb


doxygen_c:
	cat ../Doxyfile > Doxyfile_c
	echo "FILE_PATTERNS      = *.h" >> Doxyfile_c
	echo "OUTPUT_DIRECTORY   = doc_c" >> Doxyfile_c
	echo "INPUT              = ../include" >> Doxyfile_c
	echo "EXTRACT_ALL        = YES" >> Doxyfile_c
	echo "PROJECT_NAME       = \"MessagePack for C\"" >> Doxyfile_c
	doxygen Doxyfile_c

doxygen_cpp:
	cat ../Doxyfile > Doxyfile_cpp
	echo "FILE_PATTERNS      = *.hpp" >> Doxyfile_cpp
	echo "OUTPUT_DIRECTORY   = doc_cpp" >> Doxyfile_cpp
	echo "INPUT              = ../include" >> Doxyfile_cpp
	echo "EXTRACT_ALL        = YES" >> Doxyfile_cpp
	echo "PROJECT_NAME       = \"MessagePack for C++\"" >> Doxyfile_cpp
	doxygen Doxyfile_cpp

doxygen: doxygen_c doxygen_cpp
