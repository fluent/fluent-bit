import msgpack
import json

# Python script to read a MessagePack file and convert its string content to JSON

def convert_msgpack_to_json(msgpack_file, json_file):
    # Read the MessagePack file
    with open(msgpack_file, 'rb') as file:
        unpacked_data = msgpack.unpackb(file.read(), raw=False)  # Ensure string decoding
    
    # Convert the unpacked data to JSON format
    json_data = json.dumps(unpacked_data, ensure_ascii=False, indent=4)
    
    # Write the JSON data to the output file
    with open(json_file, 'w', encoding='utf-8') as file:
        file.write(json_data)
    
    print(f"MessagePack content has been converted to JSON and saved to '{json_file}'")

# Example usage
convert_msgpack_to_json('utf8_test_string_c80_to_ffff.mp', 'output.json')

