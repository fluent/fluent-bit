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
f = open("data/json_invalid.h", 'w')
write_header(f, "JSON_INVALID")
f.write("\t\"{{{{{{{{\"")
write_footer(f)
f.close()

# A really small JSON
f = open("data/json_rsmall.h", 'w')
write_header(f, "JSON_RSMALL")
write_entry(f, "key1", "value 1", None)
write_entry(f, "key2", None, "false", True)
write_footer(f)
f.close()

# Long JSON
f = open("data/json_long.h", 'w')
write_header(f, "JSON_LONG")
for i in range(0, 10000):
    write_entry(f, "key_%i" % i, "val_%i" % i, None)
write_footer(f)
f.close()
