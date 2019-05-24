## SQL Statement Syntax

The following is the SQL statement syntax supported by Fluent Bit stream processor in EBNF form. For readability, we assume the conventional definition for integer, float and string values. A single quote in a constant string literal has to be escaped with an extra one. For instance, the string representation of `O'Keefe` in the query will be `'O''Keefe'`.

```xml
<sql_stmt>    := <create> | <select>
<create>      := CREATE STREAM <id> AS <select> | CREATE STREAM <id> WITH (<properties>) AS <select>
<properties>  := <property> | <property>, <properties>
<property>    := <id> = '<id>'
<select>      := SELECT <keys> FROM <source> [WHERE <condition>] [WINDOW TUMBLING (<integer> SECOND)] [GROUP BY <record_keys>]
<keys>        := '*' | <record_keys>
<record_keys> := <record_key> | <record_key>, <record_keys>
<record_key>  := <exp> | <exp> AS <id>
<exp>         := <id> | <fun>
<fun>         := AVG(<id>) | SUM(<id>) | COUNT(<id>) | COUNT(*) | MIN(<id>) | MAX(<id>)
<source>      := STREAM:<id> | TAG:<id>
<<<<<<< HEAD
<condition>   := <id> | <value> | <id> <relation> <value> | (<condition>)
               | NOT <condition> | <condition> AND <condition> | <condition> OR <condition>
               | EXISTS <id> | <id> IS NULL | <id> IS NOT NULL
<relation>    := = | < | <= | > | >=
<id>          := <letter> <characters>
<characters>  := <letter> | <digit> | _ | <characters> <characters>
<value>       := true | false | <integer> | <float> | '<string>'
```

### Time Functions

| name             | description                                       | example             |
| ---------------- | ------------------------------------------------- | ------------------- |
| NOW()            | adds system time using format: %Y-%m-%d %H:%M:%S. | 2019-03-09 21:36:05 |
| UNIX_TIMESTAMP() | add current Unix timestamp                        | 1552196165          |

### Record Functions

| name          | description                                                  | example           |
| ------------- | ------------------------------------------------------------ | ----------------- |
| RECORD_TAG()  | append Tag string associated to the record                   | samples           |
| RECORD_TIME() | append record Timestamp in _double_ format: seconds.nanoseconds | 1552196165.705683 |
