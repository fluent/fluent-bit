
#ifndef MINIZ_EXPORT_H
#define MINIZ_EXPORT_H

#ifdef MINIZ_STATIC_DEFINE
#  define MINIZ_EXPORT
#  define MINIZ_NO_EXPORT
#else
#  ifndef MINIZ_EXPORT
#    ifdef miniz_EXPORTS
        /* We are building this library */
#      define MINIZ_EXPORT 
#    else
        /* We are using this library */
#      define MINIZ_EXPORT 
#    endif
#  endif

#  ifndef MINIZ_NO_EXPORT
#    define MINIZ_NO_EXPORT 
#  endif
#endif

#ifndef MINIZ_DEPRECATED
#  define MINIZ_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef MINIZ_DEPRECATED_EXPORT
#  define MINIZ_DEPRECATED_EXPORT MINIZ_EXPORT MINIZ_DEPRECATED
#endif

#ifndef MINIZ_DEPRECATED_NO_EXPORT
#  define MINIZ_DEPRECATED_NO_EXPORT MINIZ_NO_EXPORT MINIZ_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef MINIZ_NO_DEPRECATED
#    define MINIZ_NO_DEPRECATED
#  endif
#endif

#endif /* MINIZ_EXPORT_H */
