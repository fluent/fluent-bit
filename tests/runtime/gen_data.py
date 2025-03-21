#!/usr/bin/python

# This script generate samples at data/ directory

def write_header(handle, name):
    handle.write("#define %s\t\"[\"\t\t\\\n" % name)
    handle.write("\t\"1448403340,\"\t\t\t\\\n")
    handle.write("\t\"{\"\t\t\t\t\\\n")

def write_footer(handle):
    handle.write("\t\"\\\"END_KEY\\\": \\\"JSON_END\\\"\"\t\t\\\n")
    handle.write("\t\"}]\"\n")
    handle.write("\n")

def write_entry(handle, key, string, num_bool, eof=False):
    if string:
        handle.write(("\t\"\\\"%s\\\": \\\"%s\\\"" % (key, string)))
    else:
        handle.write(("\t\"\\\"%s\\\": %s" % (key, num_bool)))

    handle.write(",\"\t\t\\\n")

# Invalid JSON
f = open("data/common/json_invalid.h", 'w')
write_header(f, "JSON_INVALID")
f.write("\t\"{{{{{{{{\"")
write_footer(f)
f.close()

# A small JSON
f = open("data/common/json_small.h", 'w')
write_header(f, "JSON_SMALL")
for i in range(0, 250):
    write_entry(f, "key_%i" % i, None, "false", True)
write_footer(f)
f.close()

# Long JSON
f = open("data/common/json_long.h", 'w')
write_header(f, "JSON_LONG")
for i in range(0, 1000):
    write_entry(f, "key_%i" % i, "val_%i" % i, None)
write_footer(f)
f.close()

# Long JSON for TD
f = open("data/td/json_td.h", 'w')
write_header(f, "JSON_TD")
for i in range(0, 500):
    write_entry(f, "key_%i" % i, "val_%i" % i, None)
write_footer(f)
f.close()

# JSON for ES
f = open("data/es/json_es.h", 'w')
write_header(f, "JSON_ES")
write_entry(f, "key_0", None, "false")
write_entry(f, "key_1", None, "true")
write_entry(f, "key_2", "some string", None)
write_entry(f, "key_3", None, 0.12345678)
write_entry(f, "key_4", None, 5000)
write_footer(f)
f.close()
