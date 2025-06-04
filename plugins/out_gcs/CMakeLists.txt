# Google Cloud Storage Output Plugin

set(src
  gcs.c
  gcs_auth.c
  gcs_upload.c
  gcs_format.c
  )

# Check for optional Parquet support
option(FLB_OUT_GCS_PARQUET "Enable Parquet support in GCS plugin" OFF)

if(FLB_OUT_GCS_PARQUET)
    # Look for Apache Arrow library
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ARROW REQUIRED arrow)
    pkg_check_modules(PARQUET REQUIRED parquet)
    
    if(ARROW_FOUND AND PARQUET_FOUND)
        message(STATUS "Apache Arrow found, enabling Parquet support in GCS plugin")
        add_definitions(-DFLB_HAVE_PARQUET)
        
        # Add Arrow/Parquet libraries
        set(GCS_LIBS ${ARROW_LIBRARIES} ${PARQUET_LIBRARIES})
        set(GCS_INCLUDE_DIRS ${ARROW_INCLUDE_DIRS} ${PARQUET_INCLUDE_DIRS})
        set(GCS_LIBRARY_DIRS ${ARROW_LIBRARY_DIRS} ${PARQUET_LIBRARY_DIRS})
        set(GCS_CFLAGS ${ARROW_CFLAGS} ${PARQUET_CFLAGS})
    else()
        message(WARNING "Apache Arrow/Parquet not found, disabling Parquet support")
        set(FLB_OUT_GCS_PARQUET OFF)
    endif()
endif()

# Create the plugin
FLB_PLUGIN(out_gcs "${src}" "${GCS_LIBS}")

# Add include directories for Parquet support
if(FLB_OUT_GCS_PARQUET AND GCS_INCLUDE_DIRS)
    target_include_directories(flb-plugin-out_gcs PRIVATE ${GCS_INCLUDE_DIRS})
endif()

# Add library directories for Parquet support  
if(FLB_OUT_GCS_PARQUET AND GCS_LIBRARY_DIRS)
    target_link_directories(flb-plugin-out_gcs PRIVATE ${GCS_LIBRARY_DIRS})
endif()

# Add compiler flags for Parquet support
if(FLB_OUT_GCS_PARQUET AND GCS_CFLAGS)
    target_compile_options(flb-plugin-out_gcs PRIVATE ${GCS_CFLAGS})
endif()

# Required dependencies that should already be available in Fluent Bit
target_link_libraries(flb-plugin-out_gcs 
    fluent-bit-static
    )

# Installation notes for Parquet support:
# 
# To enable Parquet support, you need to install Apache Arrow C++ library:
#
# Ubuntu/Debian:
#   sudo apt-get install libarrow-dev libparquet-dev
#
# CentOS/RHEL/Fedora:
#   sudo yum install arrow-devel parquet-devel
#   # or on newer versions:
#   sudo dnf install arrow-devel parquet-devel
#
# macOS (using Homebrew):
#   brew install apache-arrow
#
# From source:
#   git clone https://github.com/apache/arrow.git
#   cd arrow/cpp
#   mkdir build && cd build
#   cmake .. -DARROW_PARQUET=ON -DARROW_BUILD_SHARED=ON
#   make -j4 && sudo make install
#
# Then configure Fluent Bit with:
#   cmake .. -DFLB_OUT_GCS_PARQUET=ON
#
# Alternative approach using Arrow GLib (C bindings):
# If you prefer C bindings instead of C++, you can use Arrow GLib:
#   sudo apt-get install libarrow-glib-dev libparquet-glib-dev
# Then modify this CMakeLists.txt to use arrow-glib instead of arrow.