PTF_CMD = sudo -E python2.7 runner.py --device stratum-bmv2 --port-map port_map.json --ptf-dir tests --cpu-port 255 --device-id 1
P4C_SRC_DIR = ../p4src
P4C_OUT = ../p4src/build

test: p4src
ifndef TEST
	$(eval TEST = all)
endif
	$(info ************ EXECUTING TESTS ************)
	${PTF_CMD} --p4info ${P4C_OUT}/p4info.txt --bmv2-json ${P4C_OUT}/bmv2.json ${TEST}

p4src:
	$(info ************ COMPILING P4 PROGRAM ************)
	cd ${P4C_SRC_DIR} && make build

%:
	make test TEST=$@

clean:
	rm -rf ptf.log
	rm -rf ptf.pcap
