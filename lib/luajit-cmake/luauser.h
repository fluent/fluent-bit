#ifndef LUA_LJDIR
#if defined(__ANDROID__)
  #if __ANDROID_API__ < 21
     #if defined(lua_getlocaledecpoint)
     #undef lua_getlocaledecpoint
     #endif

     #define lua_getlocaledecpoint()        ('.')
  #endif
  #if __ANDROID_API__ < 25
     #define fseeko fseek
     #define ftello ftell
  #endif
#endif
#if defined(__APPLE__) && defined(__MACH__)
  /* Apple OSX and iOS (Darwin). ------------------------------ */
  #include <TargetConditionals.h>
  #if (TARGET_IPHONE_SIMULATOR == 1 || TARGET_OS_IPHONE == 1)
    /* iOS in Xcode simulator */    /* iOS on iPhone, iPad, etc. */
    #define system(X)  0
  #endif
#endif
#else
#pragma clang diagnostic ignored "-Wunused-function"
#endif

