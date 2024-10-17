#!/bin/sh -e

for d in examples/processor_calyptia/*; do
  valgrind --log-file=${d##*/}-valgrind.log --leak-check=full --show-leak-kinds=all --track-origins=yes ./build/bin/fluent-bit -c ${d}/fluent-bit.yaml &
done

wait
# wait around 10 seconds, kill with ctrl+c then use `cat *-valgrind.log` to see the results
