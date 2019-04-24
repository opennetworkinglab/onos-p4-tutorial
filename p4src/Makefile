OUT_DIR=./build
P4C_BM_EXE=p4c-bm2-ss
BMV2_CPU_PORT=255
BMV2_PP_FLAGS=-DTARGET_BMV2 -DCPU_PORT=${BMV2_CPU_PORT}

all: build

build: dir
	$(P4C_BM_EXE) --arch v1model -o $(OUT_DIR)/bmv2.json \
		$(BMV2_PP_FLAGS) $(OTHER_PP_FLAGS) \
		--p4runtime-files $(OUT_DIR)/p4info.txt \
		main.p4

dir:
	mkdir -p $(OUT_DIR)

clean:
	rm -rf ./build
