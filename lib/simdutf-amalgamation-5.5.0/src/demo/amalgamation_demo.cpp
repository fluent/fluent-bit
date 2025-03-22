#include <memory>

#include "simdutf.cpp"
#include "simdutf.h"

int main(int , char *[]) {
  const char *source = "1234";
  // 4 == strlen(source)
  bool validutf8 = simdutf::validate_utf8(source, 4);
  if (validutf8) {
    puts("valid UTF-8");
  } else {
    puts("invalid UTF-8");
    return EXIT_FAILURE;
  }
  // We need a buffer of size where to write the UTF-16LE words.
  size_t expected_utf16words = simdutf::utf16_length_from_utf8(source, 4);
  std::unique_ptr<char16_t[]> utf16_output{new char16_t[expected_utf16words]};
  // convert to UTF-16LE
  size_t utf16words =
      simdutf::convert_utf8_to_utf16le(source, 4, utf16_output.get());
  printf("wrote %zu UTF-16LE words.", utf16words);
  // It wrote utf16words * sizeof(char16_t) bytes.
  bool validutf16 = simdutf::validate_utf16le(utf16_output.get(), utf16words);
  if (validutf16) {
    puts("valid UTF-16LE");
  } else {
    puts("invalid UTF-16LE");
    return EXIT_FAILURE;
  }
  // convert it back:
  // We need a buffer of size where to write the UTF-8 words.
  size_t expected_utf8words =
      simdutf::utf8_length_from_utf16le(utf16_output.get(), utf16words);
  std::unique_ptr<char[]> utf8_output{new char[expected_utf8words]};
  // convert to UTF-8
  size_t utf8words = simdutf::convert_utf16le_to_utf8(
      utf16_output.get(), utf16words, utf8_output.get());
  printf("wrote %zu UTF-8 words.", utf8words);
  std::string final_string(utf8_output.get(), utf8words);
  puts(final_string.c_str());
  if (final_string != source) {
    puts("bad conversion");
    return EXIT_FAILURE;
  } else {
    puts("perfect round trip");
  }
  return EXIT_SUCCESS;
}
