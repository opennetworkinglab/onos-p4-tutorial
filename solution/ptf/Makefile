PTF_CMD = sudo -E python2.7 runner.py --device stratum-bmv2 --port-map port_map.json --ptf-dir tests --cpu-port 255 --device-id 1
P4C_SRC_DIR = ../p4src
P4C_OUT = ../p4src/build

test: _veth-setup p4
ifndef TEST
	$(eval TEST = all)
endif
	$(info ************ EXECUTING TESTS ************)
	${PTF_CMD} --p4info ${P4C_OUT}/p4info.txt --bmv2-json ${P4C_OUT}/bmv2.json ${TEST}

p4:
	cd ${P4C_SRC_DIR} && make build

_veth-setup:
	cd ~ && sudo ./veth_setup.sh

clean:
	-rm -rf ptf.log
	-rm -rf ptf.pcap
	-rm -rf bmv2.log
	-cd ~ && sudo ./veth_teardown.sh

%:
	make test TEST=$@
