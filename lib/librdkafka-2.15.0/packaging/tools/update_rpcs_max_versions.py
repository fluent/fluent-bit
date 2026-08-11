#!/usr/bin/env python
import json
import sys
import re

# This script updates the Apache Kafka RPCs max versions.
# It reads the input from `input_file`, which should be a table
# looking like the table in `INTRODUCTION.md`.
# Should look like this (without the first space after the comment):
# | 0       | Produce                       | 12         | 10             |
# | 1       | Fetch                         | 17         | 16             |
# | 2       | ListOffsets                   | 10         | 7              |
# | 3       | Metadata                      | 13         | 12             |
# | 8       | OffsetCommit                  | 9          | 9              |
# | 9       | OffsetFetch                   | 9          | 9              |
# | 10      | FindCoordinator               | 6          | 2              |
# | 11      | JoinGroup                     | 9          | 5              |
# | 12      | Heartbeat                     | 4          | 3              |
# | 13      | LeaveGroup                    | 5          | 1              |
# | 14      | SyncGroup                     | 5          | 3              |
# | 15      | DescribeGroups                | 6          | 4              |
# | 16      | ListGroups                    | 5          | 4              |
# | 17      | SaslHandshake                 | 1          | 1              |
# | 18      | ApiVersions                   | 4          | 3              |
# | 19      | CreateTopics                  | 7          | 4              |
# | 20      | DeleteTopics                  | 6          | 1              |
# | 21      | DeleteRecords                 | 2          | 1              |
# | 22      | InitProducerId                | 5          | 4              |
# | 23      | OffsetForLeaderEpoch          | 4          | 2              |
# | 24      | AddPartitionsToTxn            | 5          | 0              |
# | 25      | AddOffsetsToTxn               | 4          | 0              |
# | 26      | EndTxn                        | 5          | 1              |
# | 28      | TxnOffsetCommit               | 5          | 3              |
# | 29      | DescribeAcls                  | 3          | 1              |
# | 30      | CreateAcls                    | 3          | 1              |
# | 31      | DeleteAcls                    | 3          | 1              |
# | 32      | DescribeConfigs               | 4          | 1              |
# | 33      | AlterConfigs                  | 2          | 2              |
# | 36      | SaslAuthenticate              | 2          | 1              |
# | 37      | CreatePartitions              | 3          | 0              |
# | 42      | DeleteGroups                  | 2          | 1              |
# | 43      | ElectLeaders                  | 2          | 2              |
# | 44      | IncrementalAlterConfigs       | 1          | 1              |
# | 47      | OffsetDelete                  | 0          | 0              |
# | 50      | DescribeUserScramCredentials  | 0          | 0              |
# | 51      | AlterUserScramCredentials     | 0          | 0              |
# | 68      | ConsumerGroupHeartbeat        | 1          | 1              |
# | 69      | ConsumerGroupDescribe         | 1          | 0              |
# | 71      | GetTelemetrySubscriptions     | 0          | 0              |
# | 72      | PushTelemetry                 | 0          | 0              |
#
# Output will be the same with max versions updated
# Should pass Apache Kafka root folder as first argument and the input file
# as second argument.
ak_folder = sys.argv[1]
input_file = sys.argv[2]

if len(sys.argv) != 3:
    print("Usage: python3 update_rpcs_max_versions.py <kafka_folder> "
          "<input_file>")
    sys.exit(1)

with open(input_file, 'r') as input:
    lines = input.readlines()
    max_first_column = 0
    max_second_column = 0
    max_third_column = 0
    apis = []
    for line in lines:
        line = re.sub('^\\s*\\|\\s*', '', line)
        pipe_char = line.find('|')
        max_first_column = max(max_first_column, pipe_char)
        api_num = int(line[0:pipe_char])
        line = line[pipe_char + 1:]
        line = re.sub('^\\s*', '', line)
        pipe_char = line.find('|')
        max_second_column = max(max_second_column, pipe_char)
        api = line[0:pipe_char].strip()
        line = line[pipe_char + 1:].lstrip()
        pipe_char = line.find('|')
        max_third_column = max(max_third_column, pipe_char)
        rest = line[pipe_char + 1:].strip()
        apis.append((api_num, api, rest))

    for api_num, api, rest in apis:
        with open(f'{ak_folder}/clients/src/main/resources/common/message/'
                  f'{api}Request.json',
                  'r') as f:
            text = f.readlines()
            text = "".join([line for line in text
                            if '#' not in line and '//' not in line])
            json_object = json.loads(text)
            max_version = json_object["validVersions"].split("-")[-1]
            print('| ', end='')
            print(str(api_num).ljust(max_first_column), end='')
            print('| ', end='')
            print(api.ljust(max_second_column), end='')
            print('| ', end='')
            print(str(max_version).ljust(max_third_column) + '|', end='')
            print(f' {rest}')
