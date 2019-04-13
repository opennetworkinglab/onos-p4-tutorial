# P4D2 SRv6 tutorial app

This directory contains the implementation of the ONOS app for the P4D2 SRv6
tutorial.

## Steps to build the app

Publish ONOS 2.1.0-SNAPSHOT artifacts locally:

```bash
onos-publish -l
```

**TODO**: update pom.xml to build against released version of ONOS 2.1.0 when
released.

Build the app:
```bash
cd app
mvn clean install
```

## Load the app in ONOS

Once ONOS is running, you can build and load the app using the following 
command:

```bash
export OCI="<onos-ip-addr>"
make load
```

Where the `$OCI` env is the address of any ONOS instance. This will uninstall
and install again  the app if already running.
