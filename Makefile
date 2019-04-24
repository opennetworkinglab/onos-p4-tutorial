p4:
	cd p4src && make build

test: veth-setup p4
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
	(ps -ef | grep apache.karaf.main.Main | grep -v grep | awk '{print $2}' | xargs kill -9 &>/dev/null) || true
	cd p4src && make clean
	cd app && make clean
	cd mininet && make clean

onos-run:
	cd ~ && ./start_onos.sh

onos-cli:
	onos

_veth-setup:
	cd ~ && sudo ./veth_setup.sh
