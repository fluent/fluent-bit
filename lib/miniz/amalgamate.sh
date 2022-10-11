#!/bin/bash

set -e

mkdir -p amalgamation

OUTPUT_PREFIX=_build/amalgamation

cmake -H. -B_build -DAMALGAMATE_SOURCES=ON -G"Unix Makefiles"

echo "int main() { return 0; }" > main.c
echo "Test compile with GCC..."
gcc -pedantic -Wall -I$OUTPUT_PREFIX main.c $OUTPUT_PREFIX/miniz.c -o test.out
echo "Test compile with GCC ANSI..."
gcc -ansi -pedantic -Wall -I$OUTPUT_PREFIX main.c $OUTPUT_PREFIX/miniz.c -o test.out
if command -v clang
then
		echo "Test compile with clang..."
        clang -Wall -Wpedantic -fsanitize=unsigned-integer-overflow -I$OUTPUT_PREFIX main.c $OUTPUT_PREFIX/miniz.c -o test.out
fi
for def in MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_DEFLATE_APIS MINIZ_NO_INFLATE_APIS MINIZ_NO_ARCHIVE_APIS MINIZ_NO_ARCHIVE_WRITING_APIS MINIZ_NO_ZLIB_APIS MINIZ_NO_ZLIB_COMPATIBLE_NAMES MINIZ_NO_MALLOC
do
	echo "Test compile with GCC and define $def..."
	gcc -ansi -pedantic -Wall -I$OUTPUT_PREFIX main.c $OUTPUT_PREFIX/miniz.c -o test.out -D${def}
done
rm test.out
rm main.c

cp $OUTPUT_PREFIX/miniz.* amalgamation/
cp ChangeLog.md amalgamation/
cp LICENSE amalgamation/
cp readme.md amalgamation/
mkdir -p amalgamation/examples
cp examples/* amalgamation/examples/

cd amalgamation
! test -e miniz.zip || rm miniz.zip
cat << EOF | zip -@ miniz
miniz.c
miniz.h
ChangeLog.md
LICENSE
readme.md
examples/example1.c
examples/example2.c
examples/example3.c
examples/example4.c
examples/example5.c
examples/example6.c
EOF
cd ..

echo "Amalgamation created."


