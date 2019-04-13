build:
	mvn clean install

load: build
	onos-app ${OCI} reinstall! target/srv6-tutorial-1.0-SNAPSHOT.oar

clean:
	rm -rf ./target
