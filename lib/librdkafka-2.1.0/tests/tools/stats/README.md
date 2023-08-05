# Stats tools

These tools are suitable for parsing librdkafka's statistics
as emitted by the `stats_cb` when `statistics.interval.ms` is set.

 * [to_csv.py](to_csv.py) - selectively convert stats JSON to CSV.
 * [graph.py](graph.py) - graph CSV files.
 * [filter.jq](filter.jq) - basic `jq` filter.

Install dependencies:

    $ python3 -m pip install -r requirements.txt


Examples:

    # Extract stats json from log line (test*.csv files are created)
    $ grep -F STATS: file.log | sed -e 's/^.*STATS: //' | ./to_csv.py test1

    # Graph toppar graphs (group by partition), but skip some columns.
    $ ./graph.py --skip '*bytes,*msg_cnt,stateage,*msgs,leader' --group-by 1partition test1_toppars.csv
