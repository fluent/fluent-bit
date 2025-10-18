import msgpack

# Python script to generate the original test string and save it as MessagePack

def generate_utf8_string():
    chars = []

    # Add normal ASCII characters (space to tilde)
    for codepoint in range(32, 127):
        chars.append(chr(codepoint))

    # Add characters from 0x80 to 0xFFFF, excluding surrogates (0xD800-0xDFFF)
    for codepoint in range(0x80, 0xD800):  # Before surrogate range
        chars.append(chr(codepoint))
    for codepoint in range(0xE000, 0x10000):  # After surrogate range
        chars.append(chr(codepoint))

    # Join them into a single string
    return ''.join(chars)

# Generate the test string
test_string = generate_utf8_string()

# Encode the string as MessagePack
encoded_msgpack_string = msgpack.packb(test_string)

# Save the encoded MessagePack string to a file
with open('utf8_test_string.msgpack', 'wb') as file:
    file.write(encoded_msgpack_string)

print("Test string has been saved as MessagePack to 'utf8_test_string.msgpack'.")
	

