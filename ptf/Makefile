PTF_CMD = sudo -E ./ptf_runner.py --device stratum-bmv2 --port-map port_map.veth.json --ptf-dir tests --cpu-port 255 --device-id 1
P4C_OUT = ../p4src/build

all: main

main:
ifndef TEST
	$(eval TEST = all)
endif
	${PTF_CMD} \
		--p4info ${P4C_OUT}/p4info.txt \
		--bmv2-json ${P4C_OUT}/bmv2.json \
		${TEST}
