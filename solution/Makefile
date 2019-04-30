ONOS_VERSION = 2.1.0-rc7
ONOS_MD5 = 6ca21242cf837a726cfbcc637107026b
ONOS_URL = http://repo1.maven.org/maven2/org/onosproject/onos-releases/$(ONOS_VERSION)/onos-$(ONOS_VERSION).tar.gz
ONOS_TAR_PATH = ~/onos.tar.gz
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
	sudo -E python ../mininet/topo.py --onos-ip ${OCI}

netcfg:
	$(info ************ PUSHING NETCFG TO ONOS ************)
	onos-netcfg ${OCI} ../netcfg.json

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

$(ONOS_TAR_PATH):
	touch $(ONOS_TAR_PATH)

LOCAL_ONOS_MD5 = $(shell md5sum $(ONOS_TAR_PATH) | awk '{print $$1}')
onos-version-check: $(ONOS_TAR_PATH)
	@if [ $(LOCAL_ONOS_MD5) = $(ONOS_MD5) ]; then echo "ONOS is already up to date"; exit 1; fi

onos-upgrade: onos-version-check
	curl $(ONOS_URL) -o $(ONOS_TAR_PATH)
