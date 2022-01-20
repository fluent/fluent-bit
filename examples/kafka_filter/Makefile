CPU_COUNT := $(shell grep -c ^processor /proc/cpuinfo)

KAFKA_TGT = kafka/done.stamp
KAFKA_DIR = $(shell dirname $(KAFKA_TGT))
CMAKE_TGT = build/done.stamp
FLB_TGT = build/bin/fluent-bit

run: $(KAFKA_TGT) $(FLB_TGT)
	./kafka-start.sh $(KAFKA_DIR) && tmux a

$(FLB_TGT): $(CMAKE_TGT)
	make -C build -j$(CPU_COUNT)

$(CMAKE_TGT):
	rm -rf build
	mkdir -pv build
	cd build && cmake -DFLB_DEV=On -DFLB_IN_KAFKA=On -DFLB_OUT_KAFKA=On ../../..
	touch $@

$(KAFKA_TGT):
	rm -rf $(KAFKA_DIR)
	./kafka-setup.sh $(KAFKA_DIR)
	touch $@

.PHONY: run
