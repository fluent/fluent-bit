## SQL Statement Syntax

The following is the SQL statement syntax supported by Fluent Bit stream processor. For readability, we assume the conventional definition for integer, float and string values. A single quote in a constant string literal has to be escaped with an extra one. For instance, the string representation of `O'Keefe` in the query will be `'O''Keefe'`.

```
<sql_stmt>    := <create> | <select>
<create>      := CREATE STREAM <id> AS <select> | CREATE STREAM <id> WITH (<properties>) AS <select>
<properties>  := <property> | <property>, <properties>
<property>    := <id> = '<id>'
<select>      := SELECT <keys> FROM <source> | SELECT <keys> FROM <source> WHERE <condition>
<keys>        := '*' | <record_keys>
<record_keys> := <record_key> | <record_key>, <record_keys>
<record_key>  := <exp> | <exp> AS <id>
<exp>         := <id> | <fun>
<fun>         := AVG(<id>) | SUM(<id>) | COUNT(<id>) | COUNT(*) | MIN(<id>) | MAX(<id>)
<source>      := STREAM:<id> | TAG:<id>
<condition>   := <id> | <value> | <id> <relation> <value> | (<condition>) | NOT <condition> | <condition> AND <condition> | <condition> OR <condition> |
<relation>    := = | < | <= | > | >=
<id>          := <letter> <characters>
<characters>  := <letter> | <digit> | _ | <characters> <characters>
<value>       := true | false | <integer> | <float> | '<string>'
```
