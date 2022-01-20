#!/bin/bash

. common.sh

java --version &> /dev/null || die "please install java 8+"

if tmux has-session -t kafka; then
	exec tmux attach -t kafka
fi

kafka_dir="$1"
[ -z $kafka_dir ] && die "usage: $0 OUTDIR"
[ ! -d $kafka_dir ] && die "$kafka_dir does not exist"
[ ! -e $kafka_dir/bin/zookeeper-server-start.sh ] && die "$kafka_dir doesn't contain kafka"

cd $kafka_dir
tmux new-session -s kafka -n "cli" -d
tmux new-window -n "services" -t kafka
tmux split-window -v -t kafka:0
tmux split-window -v -t kafka:0
tmux split-window -v -t kafka:1
tmux send-keys -t kafka:1.0 './bin/zookeeper-server-start.sh config/zookeeper.properties' C-m
tmux send-keys -t kafka:1.1 'sleep 1 && ./bin/kafka-server-start.sh config/server.properties' C-m
tmux send-keys -t kafka:0.0 'sleep 3 && ./bin/kafka-topics.sh --create --partitions 1 --replication-factor 1 --topic fb-source --bootstrap-server localhost:9092' C-m
tmux send-keys -t kafka:0.1 'sleep 3 && ./bin/kafka-topics.sh --create --partitions 1 --replication-factor 1 --topic fb-sink --bootstrap-server localhost:9092' C-m
tmux send-keys -t kafka:0.0 './bin/kafka-console-consumer.sh --topic fb-sink --from-beginning --bootstrap-server localhost:9092' C-m
tmux send-keys -t kafka:0.1 'sleep 5' C-m
tmux send-keys -t kafka:0.1 'cat ../example-data.json | ./bin/kafka-console-producer.sh --topic fb-source --bootstrap-server localhost:9092' C-m
tmux send-keys -t kafka:0.2 'sleep 4 && ../build/bin/fluent-bit -c ../kafka.conf' C-m
tmux select-window -t kafka:0.1
