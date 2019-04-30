# P4+ONOS SRv6 Tutorial

Welcome to the P4+ONOS SRv6 tutorial! The goal of this tutorial is to teach you
how to use ONOS as the control plane of a network of P4-capable devices,
controlled using P4Runtime. The tutorial is organized around a sequence of
hands-on exercises that show how to build a leaf-spine data center fabric based
on a simplified version of Segment Routing over IPv6 (SRv6). Exercises will
include activities such as:

 * P4 implementation of basic forwarding behaviors (bridging and routing) as
   well as SRv6
 * Writing P4 unit tests using the Packet Test Framework (PTF)
 * Implementing an ONOS app providing the fabric control plane

## Tutorial VM

To complete the exercises, you will need to download and run this tutorial VM
(5.3 GB):
 * <http://bit.ly/p4d2-spring19-adv-vm>
 * <http://onlab.vicci.org/onos/p4d2-spring19-adv-vm.ova> (backup)

To run the VM you can use any modern x86 virtualization system. The VM has been
tested with VirtualBox v6.0.6. To download VirtualBox and import the VM use the
following links:

 * https://www.virtualbox.org/wiki/Downloads
 * https://docs.oracle.com/cd/E26217_01/E26796/html/qs-import-vm.html

### Recommended system requirements

The VM is configured with 4 GB of RAM and 4 CPU cores, while the disk has size
of approx. 8 GB. These are the recommended minimum requirements to be able to
run Ubuntu along with a Mininet network of 1-10 BMv2 devices controlled by 1
ONOS instance. For a flawless experience, we recommend running the VM on a host
system that has at least the double of resources.

### VM user credentials

Use the following credentials to log in the Ubuntu system:

 * **Username:** `sdn`
 * **Password:** `rocks`

### Get this tutorial repo

To work on the exercises you will need to clone this repo inside the VM:

    cd ~
    git clone https://github.com/opennetworkinglab/onos-p4-tutorial tutorial

If the `tutorial` directory is already present, make sure to update its
content:

    cd ~/tutorial
    git pull origin master

### Generate SSH keys

ONOS uses SSH key-based authentication to access its command line interface
(CLI). Before starting ONOS, generate public/private rsa key pair using the
following command inside the VM:

    ssh-keygen -t rsa -f ~/.ssh/id_rsa -P '' -q

### Upgrade ONOS to the latest version used in the tutorial

The VM may have shipped with an older version of ONOS than we would like to
use for the exercises. You can upgrade to the latest version used for the
tutorial using the following command:

    make onos-upgrade

## Using an IDE to work on the exercises

During the exercises you will need to write code in multiple languages such as
P4, Python and Java. While the exercises do not prescribe the use of any
specific IDE or code editor, the tutorial VM comes with Java IDE [IntelliJ IDEA
Community Edition](https://www.jetbrains.com/idea/), already pre-loaded with
plugins for P4 syntax highlighting and Python development. We suggest using
IntelliJ IDEA especially when working on the ONOS app, as it provides code
completion for all ONOS APIs.

## Repo structure

This repo is structured as follows:

 * `p4src/` P4 implementation
 * `app/` ONOS app Java implementation
 * `mininet/` Mininet script to emulate a 2x2 leaf-spine fabric topology of
   `stratum_bmv2` devices
 * `ptf/` PTF-based unit tests

## Tutorial commands

To facilitate working on the exercises, we provide a set of make-based commands
to control the different aspects of the tutorial. Commands will be introduced in
the exercises, here's a quick reference:

| Make command        | Description                                            |
|---------------------|------------------------------------------------------- |
| `make p4`           | Builds the P4 program                                  |
| `make onos-run`     | Runs ONOS on the current terminal window               |
| `make onos-cli`     | Access the ONOS command line interface (CLI)           |
| `make app-build`    | Builds the tutorial app and pipeconf                   |
| `make app-reload`   | Load the app in ONOS                                   |
| `make topo`         | Starts the Mininet topology                            |
| `make netcfg`       | Pushes netcfg.json file (network config) to ONOS       |
| `make reset`        | Resets the tutorial environment                        |
| `make onos-upgrade` | Upgrades the ONOS version                              |

## Exercises

Click on the exercise name to see the instructions:

 1. [Software tools basics](./EXERCISE-1.md)
 2. [L2 bridging](./EXERCISE-2.md)
 3. [IPv6 routing](./EXERCISE-3.md)
 4. [Segment Routing v6](./EXERCISE-4.md)
