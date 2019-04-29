APP_OAR = app/target/srv6-tutorial-1.0-SNAPSHOT.oar

p4:
	cd p4src && make build

onos-run:
	$(info ************ STARTING ONOS ************)
	cd ~ && ./start_onos.sh

onos-cli:
	onos

topo:
	$(info ************ STARTING MININET TOPOLOGY ************)
	sudo -E python mininet/topo.py --onos-ip ${OCI}

netcfg:
	$(info ************ PUSHING NETCFG TO ONOS ************)
	onos-netcfg ${OCI} netcfg.json

app-build: p4
	$(info ************ BUILDING ONOS APP ************)
	cd app && mvn clean package

$(APP_OAR):
	$(error Missing app binary, run 'make app-build' first)

app-reload: $(APP_OAR)
	$(info ************ RELOADING ONOS APP ************)
	onos-app ${OCI} reinstall! app/target/srv6-tutorial-1.0-SNAPSHOT.oar

test-all:
	$(info ************ RUNNING ALL PTF TESTS ************)
	cd ptf && make all

reset:
	-cd ~ && ./kill_onos.sh
	-cd p4src && make clean
	-cd ptf && make clean
	-sudo rm -rf app/target
	-sudo mn -c
	-sudo rm -rf /tmp/bmv2-*
