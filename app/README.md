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

Once ONOS is running, you can load the app using the following command:

```bash
onos-app $OCI reinstall! target/p4d2-srv6-tutorial-1.0-SNAPSHOT
```

Where `$OCI` is the address of an ONOS instance.
