# hex2dec(<out-var> <input>):
# Convert a hexadecimal value <input> to decimal and write the result
# to <out-var>.
macro(hex2dec var val)
    set(${var} 0)

    set(hex2dec_idx 0)
    string(LENGTH "${val}" hex2dec_len)

    while(hex2dec_idx LESS hex2dec_len)
        string(SUBSTRING ${val} ${hex2dec_idx} 1 hex2dec_char)

        if(hex2dec_char MATCHES "[0-9]")
            set(hex2dec_char ${hex2dec_char})
        elseif(hex2dec_char MATCHES "[aA]")
            set(hex2dec_char 10)
        elseif(hex2dec_char MATCHES "[bB]")
            set(hex2dec_char 11)
        elseif(hex2dec_char MATCHES "[cC]")
            set(hex2dec_char 12)
        elseif(hex2dec_char MATCHES "[dD]")
            set(hex2dec_char 13)
        elseif(hex2dec_char MATCHES "[eE]")
            set(hex2dec_char 14)
        elseif(hex2dec_char MATCHES "[fF]")
            set(hex2dec_char 15)
        else()
            message(FATAL_ERROR "Invalid format for hexidecimal character: " ${hex2dec_char})
        endif()

        math(EXPR hex2dec_char "${hex2dec_char} << ((${hex2dec_len}-${hex2dec_idx}-1)*4)")
        math(EXPR ${var} "${${var}}+${hex2dec_char}")
        math(EXPR hex2dec_idx "${hex2dec_idx}+1")
    endwhile()
endmacro(hex2dec)

# parseversion(<filepath>):
# Parse the file given by <filepath> for the RD_KAFKA_VERSION constant
# and convert the hex value to decimal version numbers.
# Creates the following CMake variables:
# * RDKAFKA_VERSION
# * RDKAFKA_VERSION_MAJOR
# * RDKAFKA_VERSION_MINOR
# * RDKAFKA_VERSION_REVISION
# * RDKAFKA_VERSION_PRERELEASE
macro(parseversion path)
    file(STRINGS ${path} rdkafka_version_def REGEX "#define  *RD_KAFKA_VERSION  *\(0x[a-f0-9]*\)\.*")
    string(REGEX REPLACE "#define  *RD_KAFKA_VERSION  *0x" "" rdkafka_version_hex ${rdkafka_version_def})

    string(SUBSTRING ${rdkafka_version_hex} 0 2 rdkafka_version_major_hex)
    string(SUBSTRING ${rdkafka_version_hex} 2 2 rdkafka_version_minor_hex)
    string(SUBSTRING ${rdkafka_version_hex} 4 2 rdkafka_version_revision_hex)
    string(SUBSTRING ${rdkafka_version_hex} 6 2 rdkafka_version_prerelease_hex)

    hex2dec(RDKAFKA_VERSION_MAJOR ${rdkafka_version_major_hex})
    hex2dec(RDKAFKA_VERSION_MINOR ${rdkafka_version_minor_hex})
    hex2dec(RDKAFKA_VERSION_REVISION ${rdkafka_version_revision_hex})
    hex2dec(RDKAFKA_VERSION_PRERELEASE ${rdkafka_version_prerelease_hex})
    set(RDKAFKA_VERSION "${RDKAFKA_VERSION_MAJOR}.${RDKAFKA_VERSION_MINOR}.${RDKAFKA_VERSION_REVISION}")
endmacro(parseversion)
