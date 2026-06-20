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
<fun>         := AVG(<key>) | SUM(<key>) | COUNT(<key>) | COUNT(*) | MIN(<key>) | MAX(<key>) | TIMESERIES_FORECAST(<key>, <integer>)
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

In addition to the common aggregation functions, Stream Processor provides the timeseries function `TIMESERIES_FORECAST`, which uses [simple linear regression algorithm](<https://en.wikipedia.org/wiki/Simple_linear_regression) to predict the value of a (dependent) variable in future.

### Timeseries Functions

| name                      | description                                            |
| ------------------------- | ------------------------------------------------------ |
| TIMESERIES_FORECAST(x, t) | forecasts the value of x at current time + t seconds   |

### Time Functions

| name             | description                                       | example             |
| ---------------- | ------------------------------------------------- | ------------------- |
| NOW()            | adds system time using format: %Y-%m-%d %H:%M:%S  | 2019-03-09 21:36:05 |
| UNIX_TIMESTAMP() | add current Unix timestamp                        | 1552196165          |

### Record Functions

| name          | description                                                  | example           |
| ------------- | ------------------------------------------------------------ | ----------------- |
| RECORD_TAG()  | append Tag string associated to the record                   | samples           |
| RECORD_TIME() | append record Timestamp in _double_ format: seconds.nanoseconds | 1552196165.705683 |

## Type of windows

FluentBit stream processor has implemented two time-based windows: hopping window and tumbling window.

### Hopping window

In hopping window (also known as sliding window), records are stored in a time window of the interval in seconds defined as the parameter. The `ADVANCE BY` parameter determines the time the window slides forward. Aggregation functions are computed over the records inside a window, and reported right before window moves.

For example. the hopping window `WINDOW HOPPING (10 SECOND, ADVANCE BY 2 SECOND)` behaves like this:

```
[ x x x x x ... x x x x x ]
<--------- 10 sec -------->
           [ x x x x x ... x x x x x ]
<- 2 sec -><--------- 10 sec -------->
                      [ x x x x x ... x x x x x ]
           <- 2 sec -><--------- 10 sec -------->
```

### Tumbling window

A tumbling window is similar to a hopping window where `ADVANCE BY` value is the same as the window size. That means the new window doesn't include any record from the previous one.

For example. the tumbling window `WINDOW TUMBLING (10 SECOND)` works like this:

```
[ x x x x x ... x x x x x ]
<--------- 10 sec -------->
                          [ x x x x x ... x x x x x ]
                          <--------- 10 sec -------->
                                                     [ x x x x x ... x x x x x ]
                                                     <--------- 10 sec -------->
```
