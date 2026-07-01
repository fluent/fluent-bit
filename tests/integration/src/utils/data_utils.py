import os
import json

def read_output(output_path):
    with open(output_path, 'r') as file:
        return json.load(file)

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()
