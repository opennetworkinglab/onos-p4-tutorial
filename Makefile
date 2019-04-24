p4:
	cd p4src && make build

test: _veth-setup p4
	cd ptf && make test

topo: netcfg
	cd mininet && make topo

netcfg:
	cd mininet && make netcfg

app: p4
	cd app && make build

app-reload: app
	cd app && make load

reset:
	-cd ~ && ./kill_onos.sh
	-cd p4src && make clean
	-cd app && make clean
	-cd mininet && make clean

onos-run:
	cd ~ && ./start_onos.sh

onos-cli:
	onos

_veth-setup:
	cd ~ && sudo ./veth_setup.sh
