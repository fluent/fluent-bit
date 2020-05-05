## SQL Statement Syntax

The following is the SQL statement syntax supported by Fluent Bit stream processor in EBNF form. For readability, we assume the conventional definition for integer, float and string values. A single quote in a constant string literal has to be escaped with an extra one. For instance, the string representation of `O'Keefe` in the query will be `'O''Keefe'`.

```xml
<sql_stmt>    := <create> | <select>
<create>      := CREATE STREAM <id> AS <select> | CREATE STREAM <id> WITH (<properties>) AS <select>
<properties>  := <property> | <property>, <properties>
<property>    := <id> = '<id>'
<select>      := SELECT <keys> FROM <source> [WHERE <condition>]
               [WINDOW TUMBLING (<integer> SECOND) | WINDOW HOPPING (<integer> SECOND, ADVANCE BY <integer> SECOND)]
               [GROUP BY <record_keys>]
<keys>        := '*' | <record_keys>
<record_keys> := <record_key> | <record_key>, <record_keys>
<record_key>  := <exp> | <exp> AS <id>
<exp>         := <key> | <fun>
<fun>         := AVG(<key>) | SUM(<key>) | COUNT(<key>) | COUNT(*) | MIN(<key>) | MAX(<key>) | <timeseries>
<timeseries>  := FORECAST(<key>, <key>, <value>) | FORECAST_R(<key>, <key>, <value>, <value>)
<source>      := STREAM:<id> | TAG:<id>
<condition>   := <key> | <value> | <key> <relation> <value> | (<condition>)
               | NOT <condition> | <condition> AND <condition> | <condition> OR <condition>
               | @record.contains(<key>) | <id> IS NULL | <id> IS NOT NULL
<key>         := <id> | <id><subkey-idx>
<subkey-idx>  := [<id>] | <subkey-idx>[<id>]
<relation>    := = | != | <> | < | <= | > | >=
<id>          := <letter> <characters>
<characters>  := <letter> | <digit> | _ | <characters> <characters>
<value>       := true | false | <integer> | <float> | '<string>'
```

In addition to the aggregation functions, Stream Processor provides the following timeseries functions. `FORECAST` and `FORECAST_R` functions use simple linear regression algorithm as the forecasting method.

### Timeseries Functions

| name                     | description                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| FORECAST(x, y, n)        | forecasts the value of y at x + n (use RECORD_TAG() for x for time-based forecast). |
| FORECAST_R(x, y, n, cap) | forecasts the value of x (max = cap) in which y will become n.                      |

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
