# Parquet detection for Fluent Bit (Enhanced Cross-Platform Version)
# =====================================================================
# This module detects Apache Arrow and Parquet C++ libraries across multiple platforms.
#
# The following variables are set:
#   ARROW_FOUND         - System has Arrow library
#   ARROW_INCLUDE_DIRS  - Arrow include directories
#   ARROW_LIBRARIES     - Arrow libraries to link
#   PARQUET_FOUND       - System has Parquet library
#   PARQUET_INCLUDE_DIRS - Parquet include directories
#   PARQUET_LIBRARIES   - Parquet libraries to link

# Platform detection
if(WIN32)
  set(PLATFORM_NAME "Windows")
elseif(APPLE)
  set(PLATFORM_NAME "macOS")
elseif(UNIX)
  set(PLATFORM_NAME "Linux")
else()
  set(PLATFORM_NAME "Unknown")
endif()

message(STATUS "Detecting Arrow/Parquet libraries on ${PLATFORM_NAME}...")

# =============================================================================
# Method 1: Try pkg-config (Linux/macOS)
# =============================================================================
if(NOT WIN32)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(ARROW QUIET arrow)
    pkg_check_modules(PARQUET QUIET parquet)
    if(ARROW_FOUND AND PARQUET_FOUND)
      message(STATUS "Found via pkg-config")
    endif()
  endif()
endif()

# =============================================================================
# Method 2: Try CMake Config files (All platforms)
# =============================================================================
if(NOT ARROW_FOUND)
  find_package(Arrow QUIET CONFIG)
  if(Arrow_FOUND)
    set(ARROW_FOUND TRUE)
    set(ARROW_INCLUDE_DIRS ${ARROW_INCLUDE_DIR})
    # Handle both arrow_shared and arrow_static
    if(TARGET arrow_shared)
      set(ARROW_LIBRARIES arrow_shared)
    elseif(TARGET arrow_static)
      set(ARROW_LIBRARIES arrow_static)
    elseif(TARGET Arrow::arrow_shared)
      set(ARROW_LIBRARIES Arrow::arrow_shared)
    elseif(TARGET Arrow::arrow_static)
      set(ARROW_LIBRARIES Arrow::arrow_static)
    else()
      set(ARROW_LIBRARIES arrow)
    endif()
    message(STATUS "Found via CMake Config (Arrow)")
  endif()
endif()

if(NOT PARQUET_FOUND)
  find_package(Parquet QUIET CONFIG)
  if(Parquet_FOUND)
    set(PARQUET_FOUND TRUE)
    set(PARQUET_INCLUDE_DIRS ${PARQUET_INCLUDE_DIR})
    # Handle both parquet_shared and parquet_static
    if(TARGET parquet_shared)
      set(PARQUET_LIBRARIES parquet_shared)
    elseif(TARGET parquet_static)
      set(PARQUET_LIBRARIES parquet_static)
    elseif(TARGET Parquet::parquet_shared)
      set(PARQUET_LIBRARIES Parquet::parquet_shared)
    elseif(TARGET Parquet::parquet_static)
      set(PARQUET_LIBRARIES Parquet::parquet_static)
    else()
      set(PARQUET_LIBRARIES parquet)
    endif()
    message(STATUS "Found via CMake Config (Parquet)")
  endif()
endif()

# =============================================================================
# Method 3: Manual search with platform-specific paths
# =============================================================================
if(NOT ARROW_FOUND OR NOT PARQUET_FOUND)
  # Define search paths based on platform
  if(WIN32)
    # Windows paths (vcpkg, manual install, choco)
    set(SEARCH_PATHS
      "$ENV{VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}"
      "C:/vcpkg/installed/${VCPKG_TARGET_TRIPLET}"
      "C:/Program Files/Arrow"
      "C:/Program Files (x86)/Arrow"
      "$ENV{ProgramFiles}/Arrow"
      "$ENV{ProgramFiles(x86)}/Arrow"
      "$ENV{LOCALAPPDATA}/Arrow"
    )
    set(LIB_SUFFIXES lib)
    set(INCLUDE_SUFFIXES include)
    set(ARROW_LIB_NAMES arrow arrow_static)
    set(PARQUET_LIB_NAMES parquet parquet_static)
  elseif(APPLE)
    # macOS paths (Homebrew, MacPorts, manual)
    # Detect Apple Silicon vs Intel
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE ARCH
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(ARCH STREQUAL "arm64")
      set(HOMEBREW_PREFIX "/opt/homebrew")
    else()
      set(HOMEBREW_PREFIX "/usr/local")
    endif()

    set(SEARCH_PATHS
      ${HOMEBREW_PREFIX}
      /opt/local          # MacPorts
      /usr/local
      $ENV{HOME}/.local
    )
    set(LIB_SUFFIXES lib)
    set(INCLUDE_SUFFIXES include)
    set(ARROW_LIB_NAMES arrow libarrow)
    set(PARQUET_LIB_NAMES parquet libparquet)
  else()
    # Linux paths (apt, yum, manual)
    set(SEARCH_PATHS
      /usr
      /usr/local
      /opt/arrow
      /opt/local
      $ENV{HOME}/.local
    )
    # Check for 64-bit vs 32-bit
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(LIB_SUFFIXES lib64 lib lib/x86_64-linux-gnu)
    else()
      set(LIB_SUFFIXES lib lib/i386-linux-gnu)
    endif()
    set(INCLUDE_SUFFIXES include)
    set(ARROW_LIB_NAMES arrow libarrow)
    set(PARQUET_LIB_NAMES parquet libparquet)
  endif()

  # Search for Arrow
  if(NOT ARROW_FOUND)
    find_path(ARROW_INCLUDE_DIR
      NAMES arrow/api.h
      PATHS ${SEARCH_PATHS}
      PATH_SUFFIXES ${INCLUDE_SUFFIXES}
      NO_DEFAULT_PATH
    )

    find_library(ARROW_LIBRARY
      NAMES ${ARROW_LIB_NAMES}
      PATHS ${SEARCH_PATHS}
      PATH_SUFFIXES ${LIB_SUFFIXES}
      NO_DEFAULT_PATH
    )

    if(ARROW_INCLUDE_DIR AND ARROW_LIBRARY)
      set(ARROW_FOUND TRUE)
      set(ARROW_INCLUDE_DIRS ${ARROW_INCLUDE_DIR})
      set(ARROW_LIBRARIES ${ARROW_LIBRARY})
      message(STATUS "Found via manual search (Arrow)")
    endif()
  endif()

  # Search for Parquet
  if(NOT PARQUET_FOUND)
    find_path(PARQUET_INCLUDE_DIR
      NAMES parquet/api/reader.h
      PATHS ${SEARCH_PATHS}
      PATH_SUFFIXES ${INCLUDE_SUFFIXES}
      NO_DEFAULT_PATH
    )

    find_library(PARQUET_LIBRARY
      NAMES ${PARQUET_LIB_NAMES}
      PATHS ${SEARCH_PATHS}
      PATH_SUFFIXES ${LIB_SUFFIXES}
      NO_DEFAULT_PATH
    )

    if(PARQUET_INCLUDE_DIR AND PARQUET_LIBRARY)
      set(PARQUET_FOUND TRUE)
      set(PARQUET_INCLUDE_DIRS ${PARQUET_INCLUDE_DIR})
      set(PARQUET_LIBRARIES ${PARQUET_LIBRARY})
      message(STATUS "Found via manual search (Parquet)")
    endif()
  endif()
endif()

# =============================================================================
# Validation and Version Check
# =============================================================================
if(ARROW_FOUND)
  # Try to detect Arrow version
  if(EXISTS "${ARROW_INCLUDE_DIRS}/arrow/util/config.h")
    file(STRINGS "${ARROW_INCLUDE_DIRS}/arrow/util/config.h"
         ARROW_VERSION_LINE REGEX "^#define ARROW_VERSION_STRING")
    if(ARROW_VERSION_LINE)
      string(REGEX REPLACE "^#define ARROW_VERSION_STRING \"([0-9.]+)\".*" "\\1"
             ARROW_VERSION ${ARROW_VERSION_LINE})
      message(STATUS "Arrow version: ${ARROW_VERSION}")

      # Check minimum version (e.g., 10.0.0)
      if(ARROW_VERSION VERSION_LESS "10.0.0")
        message(WARNING "Arrow version ${ARROW_VERSION} is older than recommended 10.0.0")
      endif()
    endif()
  endif()
endif()

# =============================================================================
# Report results with installation hints
# =============================================================================
if(ARROW_FOUND AND PARQUET_FOUND)
  message(STATUS "✓ Arrow found: ${ARROW_LIBRARIES}")
  message(STATUS "  Include dirs: ${ARROW_INCLUDE_DIRS}")
  message(STATUS "✓ Parquet found: ${PARQUET_LIBRARIES}")
  message(STATUS "  Include dirs: ${PARQUET_INCLUDE_DIRS}")
else()
  message(STATUS "✗ Arrow/Parquet not found")

  if(FLB_PARQUET_ENCODER)
    message(WARNING "FLB_PARQUET_ENCODER is enabled but Arrow/Parquet libraries not found.")
    message(WARNING "")
    message(WARNING "Installation instructions:")

    if(WIN32)
      message(WARNING "  Windows (vcpkg):")
      message(WARNING "    vcpkg install arrow:x64-windows parquet:x64-windows")
      message(WARNING "    cmake -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake ..")
      message(WARNING "")
      message(WARNING "  Windows (pre-built):")
      message(WARNING "    Download from: https://arrow.apache.org/install/")
    elseif(APPLE)
      message(WARNING "  macOS (Homebrew):")
      message(WARNING "    brew install apache-arrow")
      message(WARNING "")
      message(WARNING "  macOS (MacPorts):")
      message(WARNING "    sudo port install apache-arrow")
    else()
      message(WARNING "  Ubuntu/Debian:")
      message(WARNING "    sudo apt-get install -y -V ca-certificates lsb-release wget")
      message(WARNING "    wget https://packages.apache.org/artifactory/arrow/$(lsb_release --id --short | tr 'A-Z' 'a-z')/apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb")
      message(WARNING "    sudo apt-get install -y -V ./apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb")
      message(WARNING "    sudo apt-get update")
      message(WARNING "    sudo apt-get install -y -V libarrow-dev libparquet-dev")
      message(WARNING "")
      message(WARNING "  RHEL/CentOS:")
      message(WARNING "    sudo yum install -y https://packages.apache.org/artifactory/arrow/centos/$(cut -d: -f5 /etc/system-release-cpe | cut -d. -f1)/apache-arrow-release-latest.rpm")
      message(WARNING "    sudo yum install -y arrow-devel parquet-devel")
    endif()

    message(WARNING "")
    message(WARNING "Or disable with: -DFLB_PARQUET_ENCODER=Off")
  endif()
endif()

# =============================================================================
# Export variables to parent scope
# =============================================================================
set(ARROW_FOUND ${ARROW_FOUND} PARENT_SCOPE)
set(ARROW_INCLUDE_DIRS ${ARROW_INCLUDE_DIRS} PARENT_SCOPE)
set(ARROW_LIBRARIES ${ARROW_LIBRARIES} PARENT_SCOPE)
set(PARQUET_FOUND ${PARQUET_FOUND} PARENT_SCOPE)
set(PARQUET_INCLUDE_DIRS ${PARQUET_INCLUDE_DIRS} PARENT_SCOPE)
set(PARQUET_LIBRARIES ${PARQUET_LIBRARIES} PARENT_SCOPE)

# Export version if found
if(DEFINED ARROW_VERSION)
  set(ARROW_VERSION ${ARROW_VERSION} PARENT_SCOPE)
endif()
