# Cannot convert to Android.bp as resource copying has not
# yet implemented for soong as of 12/16/2016

LOCAL_PATH := $(call my-dir)

# config/vsomeip.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

# config/vsomeip-local.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip-local.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip-local.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

# config/vsomeip-tcp-client.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip-tcp-client.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip-tcp-client.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

# config/vsomeip-tcp-service.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip-tcp-service.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip-tcp-service.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

# config/vsomeip-udp-client.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip-udp-client.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip-udp-client.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

# config/vsomeip-udp-service.json config file
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := vsomeip-udp-service.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/etc/vsomeip
LOCAL_SRC_FILES := config/vsomeip-udp-service.json
LOCAL_PROPRIETARY_MODULE := true
#include $(BUILD_PREBUILT)

#
# libvsomeip3_dlt
#
include $(CLEAR_VARS)

LOCAL_MODULE := libvsomeip3_dlt
LOCAL_MODULE_TAGS := optional
LOCAL_CLANG := true
LOCAL_PROPRIETARY_MODULE := true

LOCAL_EXPORT_C_INCLUDE_DIRS :=   $(LOCAL_PATH)/interface \

LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/endpoints)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/logger)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/tracing)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/message)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/routing)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/runtime)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/utility)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/plugin)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/security)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/interface \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libutils \
    libboost_system \
    libboost_thread \
    libboost_filesystem \

LOCAL_CFLAGS :=  \
    -std=c++17 \
    -frtti \
    -fexceptions \
    -DWITHOUT_SYSTEMD \
    -DVSOMEIP_VERSION=\"3.5.1\" \
    -DVSOMEIP_BASE_PATH=\"/vendor/run/someip/\" \
    -Wno-unused-parameter \
    -Wno-non-virtual-dtor \
    -Wno-unused-const-variable \
    -Wno-unused-parameter \
    -Wno-unused-private-field \
    -Wno-unused-lambda-capture \
    -Wno-unused-variable \
    -Wno-unused-local-typedef \
    -Wno-sign-compare \
    -Wno-format \
    -Wno-header-guard \
    -Wno-overloaded-virtual \

include $(BUILD_SHARED_LIBRARY)

#
# libvsomeip-cfg_dlt
#
include $(CLEAR_VARS)

LOCAL_MODULE := libvsomeip-cfg_dlt
LOCAL_MODULE_TAGS := optional
LOCAL_CLANG := true
LOCAL_PROPRIETARY_MODULE := true

LOCAL_EXPORT_C_INCLUDE_DIRS :=   $(LOCAL_PATH)/interface \

LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/configuration)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/interface \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libutils \
    libboost_system \
    libboost_thread \
    libboost_filesystem \
    libvsomeip3_dlt \

LOCAL_CFLAGS := \
    -std=c++17 \
    -frtti \
    -fexceptions \
    -DWITHOUT_SYSTEMD \
    -DVSOMEIP_VERSION=\"3.5.1\" \
    -DVSOMEIP_BASE_PATH=\"/vendor/run/someip/\" \
    -Wno-unused-parameter \
    -Wno-non-virtual-dtor \
    -Wno-unused-const-variable \
    -Wno-unused-parameter \
    -Wno-unused-private-field \
    -Wno-unused-lambda-capture \
    -Wno-unused-variable \
    -Wno-unused-local-typedef \
    -Wno-sign-compare \
    -Wno-format \
    -Wno-header-guard \
    -Wno-overloaded-virtual \

include $(BUILD_SHARED_LIBRARY)

#
# libvsomeip_dlt
#
include $(CLEAR_VARS)

LOCAL_MODULE := libvsomeip_dlt
LOCAL_MODULE_TAGS := optional
LOCAL_CLANG := true
LOCAL_PROPRIETARY_MODULE := true

LOCAL_EXPORT_C_INCLUDE_DIRS :=   $(LOCAL_PATH)/interface \

LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/compat/message)
LOCAL_SRC_FILES += $(call all-cpp-files-under,implementation/compat/runtime)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/interface \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libutils \
    libboost_system \
    libboost_thread \
    libboost_filesystem \
    libvsomeip3_dlt \

LOCAL_CFLAGS :=  \
    -frtti \
    -fexceptions \
    -DWITHOUT_SYSTEMD \
    -DVSOMEIP_VERSION=\"3.5.1\" \
    -DVSOMEIP_COMPAT_VERSION=\"3.5.1\" \
    -DVSOMEIP_BASE_PATH=\"/vendor/run/someip/\" \
    -Wno-unused-parameter \
    -Wno-non-virtual-dtor \
    -Wno-unused-const-variable \
    -Wno-unused-parameter \
    -Wno-unused-private-field \
    -Wno-unused-lambda-capture \
    -Wno-unused-variable \
    -Wno-unused-local-typedef \
    -Wno-sign-compare \
    -Wno-format \
    -Wno-header-guard \
    -Wno-overloaded-virtual \
    -Wl,-wrap,socket \
    -Wl,-wrap,accept \
    -Wl,-wrap,open \

include $(BUILD_SHARED_LIBRARY)
