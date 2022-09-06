#include "lib_export.h"

#ifdef APP_FRAMEWORK_SENSOR
#include "sensor_native_api.h"
#endif

#ifdef APP_FRAMEWORK_CONNECTION
#include "connection_native_api.h"
#endif

#ifdef APP_FRAMEWORK_WGL
#include "gui_native_api.h"
#endif

/* More header file here */

static NativeSymbol extended_native_symbol_defs[] = {
#ifdef APP_FRAMEWORK_SENSOR
#include "runtime_sensor.inl"
#endif

#ifdef APP_FRAMEWORK_CONNECTION
#include "connection.inl"
#endif

#ifdef APP_FRAMEWORK_WGL
#include "wamr_gui.inl"
#endif

    /* More inl file here */
};

int
get_ext_lib_export_apis(NativeSymbol **p_ext_lib_apis)
{
    *p_ext_lib_apis = extended_native_symbol_defs;
    return sizeof(extended_native_symbol_defs) / sizeof(NativeSymbol);
}
