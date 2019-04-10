# P4Runtime PTF tests

## Dependencies (on the test machine)

- [ptf](https://github.com/p4lang/ptf)
- [scapy with extensions](https://github.com/p4lang/scapy-vxlan)
- [P4Runtime](https://github.com/p4lang/PI#building-p4runtimeproto): the
protobuf / gRPC Python code for P4Runtime must have been generated and installed
in the Python path.
- [BMv2](https://github.com/p4lang/behavioral-model/blob/master/targets/simple_switch_grpc)
- Stratum (optional)

### ONOS+P4 Developer VM

Alternatively, you can download this VM with all the necessary dependencies already installed:

[Instructions to download and use the ONOS+P4 Developer VM](https://wiki.onosproject.org/x/FYnV#P4RuntimesupportinONOS-ONOS+P4DeveloperVM)

The link provides also instructions to use Vagrant to build the VM locally.


## Compiling the P4 program

Before running tests, you need to build the P4 program:

```
cd p4src
make
```

Compiler output used for tests, such as the BMv2 JSON and P4Info file, will be
placed under `p4src/build`.


## Steps to run the tests with BMv2

1. Setup veth interfaces, using the script provided with BMv2. This script
should be executed only once before executing any PTF test, or after a reboot
of the test machine.

    ```
    cd <path to bmv2 repo>/tools
    sudo ./veth_setup.sh
    ```

If using the ONOS-P4 Dev VM, the `veth_setup.sh` script will be located
under `/home/sdn`.

2. Run the PTF tests using a convenient `make` command:

    ```
    cd ptf
    make
    ```
    
    To run a specific test case or group of tests:

    ```
    make TEST=<test-or-group-name>
    ```
    
    For example:
    
    ```
    make TEST=test.FabricBridgingTest
    make TEST=packetio
    ```


## Port map JSON file

This file is required to let PTF know which test interface corresponds to which
P4 dataplane port number. Consider the following test topology:

```
             ASIC under test
******************************************
148          149          134          135
 |            |            |            |
 |            |            |            |
 |            |            |            |
ens2f0       ens2f1       ens2f2       ens2f3
******************************************
              PTF test server
```

For this topology one may use the following port map JSON file:
```
[
    {
        "ptf_port": 0,
        "p4_port": 148,
        "iface_name": "ens2f0"
    },
    {
        "ptf_port": 1,
        "p4_port": 149,
        "iface_name": "ens2f1"
    },
    {
        "ptf_port": 2,
        "p4_port": 134,
        "iface_name": "ens2f2"
    },
    {
        "ptf_port": 3,
        "p4_port": 135,
        "iface_name": "ens2f3"
    }
]
```

The `"ptf_port"` is the id used to reference the port in the Python PTF
tests. As of now, `"ptf_port"` must be equal to the index of the entry in the
port map JSON array of interfaces. Port numbers must never be used directly when
calling PTF Python functions (e.g. `send_packet`); instead, when writing your
own tests, call the `swports` method which will map the `"ptf_port"` to the
`"p4_port"` based on the provided port map JSON file.
