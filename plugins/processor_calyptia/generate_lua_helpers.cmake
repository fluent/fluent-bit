# cmake script which converts a lua helpers file into a C header for embedding
# in the executable
set(INPUT_FILE ${CMAKE_ARGV3})
set(OUTPUT_FILE ${CMAKE_ARGV4})

file(READ ${INPUT_FILE} content HEX)
string(REGEX MATCHALL "([A-Fa-f0-9][A-Fa-f0-9])" SEPARATED_HEX ${content})

# Create a counter so that we only have 16 hex bytes per line
set(counter 0)
# Iterate through each of the bytes from the source file
foreach (hex IN LISTS SEPARATED_HEX)
  # Write the hex string to the line with an 0x prefix
  # and a , postfix to seperate the bytes of the file.
  string(APPEND output_c "0x${hex},")
  # Increment the element counter before the newline.
  math(EXPR counter "${counter}+1")
  if (counter GREATER 16)
    # Write a newline so that all of the array initializer
    # gets spread across multiple lines.
    string(APPEND output_c "\n    ")
    set(counter 0)
  endif ()
endforeach ()

set(c_name calyptia_processor_lua_helpers)
set(output_c "
char ${c_name}[] = {
${output_c} 0x0
}\;
")

file(WRITE ${OUTPUT_FILE} ${output_c})
