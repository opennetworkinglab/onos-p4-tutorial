# Exercise 1: Software tools basics and packet I/O

This exercise provides a hands-on introduction to the software tools used in
the rest of the tutorial.

As a start, in this exercise you will learn how to:

1. Start Mininet with a 2x2 leaf-spine topology of `stratum_bmv2` software
   switches
2. Start ONOS along with a set of built-in apps for basic services such as
   topology discovery
3. Push a networking configuration file to ONOS to discover and control the
   `stratum_bmv2` switches using P4Runtime
4. Verify that ONOS is able to automatically discover all links by using
   P4Runtime packet-in/out

To accomplish this you will be asked to apply simple changes to the starter P4
code to add support for packet-in, validate the P4 changes by means of PTF-based
data plane unit tests, and finally, apply changes to the pipeconf Java
implementation to let ONOS built-in apps perform topology discovery using
packet-in/out.

## Controller packet I/O with P4Runtime

The P4 program under `p4src/` provides support for carrying arbitrary metadata
in P4Runtime `PacketIn` and `PacketOut` messages. Two special headers are
defined and annotated with the standard P4 annotation `@controller_header`:

```
@controller_header("packet_in")
header packet_in_header_t {
    port_num_t ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out")
header packet_out_header_t {
    port_num_t egress_port;
    bit<7> _pad;
}
```

These headers are used to carry the original switch ingress port of a packet-in,
and specify the intended output port for a packet-out.

When the P4Runtime agent in Stratum receives a packet from the CPU port, it
expects to find the `packet_in_header_t` header as the first one in the frame.
Indeed, it looks at the `ControllerPacketMetadata` part of the P4Info file to
determine the number of bits to strip at the beginning of the frame and to
populate the corresponding `PacketIn.metadata` fields, including the ingress
port as in this case.

Similarly, when Stratum receives a P4Runtime `PacketOut` message, it uses the
values found in the `PacketOut.metadata` fields to serialize and prepend a
`packet_out_header_t` to the `PacketOut.payload` before feeding it to the
pipeline parser.

## Exercise steps

### 1. Modify P4 program

The P4 starter code already provides support for the following capabilities:

* Parser for `packet_out` header (if ingress port is the CPU one)
* Emit of `packet_in` header in the deparser as the first one.
* For packet-out, skip ingress pipeline processing, and set egress port as
  specified in the `packet_out` header;
* ACL-like table with all ternary match fields and action to clone
  packets to the CPU port and hence generate a packet-in;

One piece is missing to have complete packet-in support and you have to modify
the P4 program to implement it:

1. Open `p4src/main.p4`;
2. Look for the implementation of the egress pipeline (`control FabricEgress`);
3. Modify the code where requested (look for `TODO EXERCISE 1`);
4. Compile the modified P4 program using the `make p4` command.

The last command will produce two output files under `p4src/build`:

* `bmv2.json`: BMv2 JSON pipeline configuration
* `p4info.txt`: P4Info file in protobuf text format

### 2. Run PTF tests

Before starting ONOS, let's make sure the P4 changes work as expected by
running some PTF tests. But first, you need to apply a few simple changes to the
test case implementation.

Open file `ptf/tests/packetio.py` and modify wherever requested (look for `TODO
EXERCISE 1`). This test file provides two test case, for packet-in and
packet-out. In both test cases, you will have to modify the implementation to
use the same name for P4Runtime entities as specified in the P4Info file
obtained after compiling the P4 program (`p4src/build/p4info.txt`).

To run all the tests for this exercise:

    cd ptf
    make packetio

This command will run all tests in the `packetio` group (i.e. the content of
`ptf/tests/packetio.py`). To run a specific test case you can use:

    make <PYTHON MODULE>.<TEST CASE NAME>

For example:

    make packetio.PacketOutTest

If all tests succeed, congratulations! You can move to the next step.

**How to debug failing tests?**

When running PTF tests, multiple files are produced that you can use to spot bugs:

* `ptf/bmv2.log`: BMv2 log with trace level (showing tables matched and other
  info for each packet)
* `ptf/ptf.pcap`: PCAP file with all packets sent and received during tests
  (the tutorial VM comes with Wireshark for easier visualization)
* `ptf/ptf.log`: PTF log of all packet operations (sent and received)

### 3. Modify ONOS pipeline interpreter

The `PipelineInterpreter` is the ONOS driver behavior used to map, among other
things, the ONOS representation of packet-in/out, with one compliant with the P4
implementation.

Specifically, to use services like LLDP-based link discovery, ONOS built-in
apps need to be able to set the output port of a packet-out and access the
original ingress port of a packet-in.

In the following, you will be asked to apply a few simple changes to the
`PipelineInterpreter` implementation:

1. Open file:
   `app/src/main/java/org/p4/p4d2/tutorial/pipeconf/InterpreterImpl.java`

2. Modify wherever requested (look for `TODO EXERCISE 1`), specifically:

    * Look for a method named `buildPacketOut`, modify the implementation to use the
      same name of the **egress port** metadata field for the `packet_out`
      header as specified in the P4Info file.

    * Look for method `mapInboundPacket`, modify the implementation to use the
      same name of the **ingress port** metadata field for the `packet_in`
      header as specified in the P4Info file.

3. Build ONOS app (including the pipeconf) with the command `make app-build`.

The last command will trigger a build of the P4 program if necessary. The P4
compiler outputs (`bmv2.json` and `p4info.txt`) are symlinked in the app
resource folder (`app/src/main/resources`) and will be included in the ONOS app
binary.

### 4. Start ONOS

In a terminal window, type:

```
$ make onos-run
```

This command will start a clean installation of ONOS (i.e. removing any state
from previous executions). During the start procedure, the value of the
environment variable `$ONOS_APPS` is used to define the built-in apps to load
during startup.

In the tutorial VM this variable has value:

```
$ echo $ONOS_APPS
gui,drivers.bmv2,lldpprovider,hostprovider
```

Requesting ONOS to pre-load the following built-in apps:

* `gui`: ONOS web user interface (available at <http://localhost:8181/onos/ui>)
* `drivers.bmv2`: BMv2/Stratum drivers based on P4Runtime, gNMI, and gNOI
* `lldpprovider`: LLDP-based link discovery application
* `hostprovider`: Host discovery application


Once ONOS has started, you should see the log being printed on the screen. ONOS
is ready to be used when the following log message is printed (it should be the
last one):

```
INFO  [AtomixClusterStore] Updated node 127.0.0.1 state to READY
```

To **verify that all required apps have been activated**, run the following
command to access the ONOS CLI:

```
make onos-cli
```

Type the following command in the ONOS CLI to show the list of running apps:

```
onos> apps -a -s
```

Make sure you see the following list of apps displayed:

```
* ... org.onosproject.lldpprovider          ... LLDP Link Provider
* ... org.onosproject.drivers               ... Default Drivers
* ... org.onosproject.protocols.grpc        ... gRPC Protocol Subsystem
* ... org.onosproject.protocols.gnmi        ... gNMI Protocol Subsystem
* ... org.onosproject.generaldeviceprovider ... General Device Provider
* ... org.onosproject.protocols.p4runtime   ... P4Runtime Protocol Subsystem
* ... org.onosproject.p4runtime             ... P4Runtime Provider
* ... org.onosproject.drivers.p4runtime     ... P4Runtime Drivers
* ... org.onosproject.pipelines.basic       ... Basic Pipelines
* ... org.onosproject.drivers.gnmi          ... gNMI Drivers
* ... org.onosproject.protocols.gnoi        ... gNOI Protocol Subsystem
* ... org.onosproject.drivers.gnoi          ... gNOI Drivers
* ... org.onosproject.drivers.stratum       ... Stratum Drivers
* ... org.onosproject.hostprovider          ... Host Location Provider
* ... org.onosproject.gui                   ... ONOS Legacy GUI
* ... org.onosproject.drivers.bmv2          ... BMv2 Drivers
```

This is definitely more apps than what defined in `$ONOS_APPS`. That's
because each app in ONOS can define other apps as dependencies. When loading an
app, ONOS automatically resolve dependencies and loads all other required apps.

**Restart ONOS in case of errors**

If anything goes wrong and you need to kill/restart ONOS, press `Ctrl+C` in the
same terminal window where you started ONOS (and the log is printed).
alternatively, you can use command `make reset`. To restart ONOS execute `make
onos-run`.

### 5. Load app and register pipeconf

On a second terminal window, type:

```
$ make app-reload
```

This command will uploads to ONOS and activate the app binary previously built
(located at`app/target/srv6-tutorial-1.0-SNAPSHOT.oar`).

After the app has been activated, you should see the following messages in the
log signaling that the pipeconf has been registered and the different app
components have been started:

```
INFO  [PiPipeconfManager] New pipeconf registered: org.p4.srv6-tutorial (fingerprint=...)
INFO  [MainComponent] Started
```

Alternatively, you can show the list of registered pipeconfs using the ONOS CLI
command:

```
onos> pipeconfs
```

**Reloading the app after the first time**

If another instance of the same app is running, the command `make app-reload`
will first deactivate the running instance and load the new one.

To apply new changes to the P4 program or app implementation, feel free to use
`make app-build && make app-reload` as many times as you want. The app already
includes logic to clean up any table entries and other forwarding states from
ONOS at each reload.

### 6. Start Mininet topology

On a third terminal window, type:

```
$ make topo
```

This command will start the Mininet-based topology script (`mininet/topo.py`).
This script creates the 2x2 fabric topology described before and starts the
Mininet CLI.

As part of this process, a set of files are generated in `/tmp`. For example,
the log of each `stratum_bmv2` instance can be found in
`/tmp/bmv2-log-<switch-name>`, where switch name can be `leaf1`, `leaf2`,
`spine1`, `spine2`. This log file combines messages from both the Stratum
process (e.g. P4Runtime operations) and BMv2 `simple_switch`.

If you want to follow the `stratum_bmv2` log updating in real time, you can use
the following command to print on screen all new messages:

```
$ bm-log leaf1
```

### 4. Push netcfg to ONOS

Now that ONOS and Mininet are running, it's time to let ONOS know how to reach
the 4 switches and control them.

On a fourth terminal window, type:

```
$ make netcfg
```

This command will use the netcfg JSON file (`netcfg.json`) to ONOS, triggering
discovery and configuration of the 4 switches.

You should see in the log messages like:

```
INFO  [GrpcChannelControllerImpl] Creating new gRPC channel grpc://127.0.0.1:50001?device_id=1...
...
INFO  [StreamClientImpl] Setting mastership on device:leaf1...
...
INFO  [PipelineConfigClientImpl] Setting pipeline config for device:leaf1 to org.p4.srv6-tutorial...
...
INFO  [GnmiDeviceStateSubscriber] Started gNMI subscription for 6 ports on device:leaf1
...
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth1](1) status changed (enabled=true)
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth2](2) status changed (enabled=true)
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth3](3) status changed (enabled=true)
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth4](4) status changed (enabled=true)
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth5](5) status changed (enabled=true)
INFO  [DeviceManager] Device device:leaf1 port [leaf1-eth6](6) status changed (enabled=true)
```

### 5. Use ONOS CLI to verify network configuration

Access the ONOS CLI using `make onos-cli`. Enter the following command to
verify the network config pushed before:

```
onos> netcfg
```

#### Devices

Verify that all 4 devices have been discovered and are connected:

```
onos> devices -s
id=device:leaf1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.p4.srv6-tutorial
id=device:leaf2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.p4.srv6-tutorial
id=device:spine1, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.p4.srv6-tutorial
id=device:spine2, available=true, role=MASTER, type=SWITCH, driver=stratum-bmv2:org.p4.srv6-tutorial
```

Make sure `available=true` for all devices.

#### Interfaces

Verify that 6 interfaces are configured in ONOS as in the netcfg file, 4 for
`leaf1` and 2 for `leaf2`, each one with one IPv6 address assigned:

```
onos> interfaces
leaf1-3: port=device:leaf1/3 ips=[2001:1:1::ff/64]
leaf1-4: port=device:leaf1/4 ips=[2001:1:1::ff/64]
leaf1-5: port=device:leaf1/5 ips=[2001:1:1::ff/64]
leaf1-6: port=device:leaf1/6 ips=[2001:1:2::ff/64]
leaf2-3: port=device:leaf2/3 ips=[2001:1:3::ff/64]
leaf2-4: port=device:leaf2/4 ips=[2001:1:4::ff/64]
```

This IPv6 address configuration will be used later to provide routing
capabilities.

#### Links

Verify that all links have been discovered. You should see 8 links in total:

```
onos> links
src=device:leaf1/1, dst=device:spine1/1, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf1/2, dst=device:spine2/1, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf2/1, dst=device:spine1/2, type=DIRECT, state=ACTIVE, expected=false
src=device:leaf2/2, dst=device:spine2/2, type=DIRECT, state=ACTIVE, expected=false
src=device:spine1/1, dst=device:leaf1/1, type=DIRECT, state=ACTIVE, expected=false
src=device:spine1/2, dst=device:leaf2/1, type=DIRECT, state=ACTIVE, expected=false
src=device:spine2/1, dst=device:leaf1/2, type=DIRECT, state=ACTIVE, expected=false
src=device:spine2/2, dst=device:leaf2/2, type=DIRECT, state=ACTIVE, expected=false
```

**If you don't see any link**, check the ONOS log for any error with
packet-in/out handling. In case of errors, it's possible that you have not
modified `InterpreterImpl.java` correctly. In this case, kill ONOS and go back
to exercise step 3.

**Note:** in theory, there should be no need to kill and restart ONOS. However,
while ONOS supports reloading the pipeconf with a modified one (e.g., with
updated `bmv2.json` and `p4info.txt`), the version of ONOS used in this tutorial
(2.1.0, the most recent at the time of writing) does not support reloading the
pipeconf behavior classes, in  which case the old classes will still be used.
For this reason, to reload a modified version of `InterpreterImpl.java`, you
need to kill ONOS first.

#### Flow rules and groups

Verify flow rules, you should see 5 flow rules for each device. For example, to
show all flow rules installed so far on device `leaf1`:

```
onos> flows -s any device:leaf1
deviceId=device:leaf1, flowRuleCount=5
    ADDED, ..., table=FabricIngress.acl, priority=40000, selector=[ETH_TYPE:ipv6, IP_PROTO:58, ICMPV6_TYPE:136], treatment=[immediate=[FabricIngress.clone_to_cpu()]]
    ADDED, ..., table=FabricIngress.acl, priority=40000, selector=[ETH_TYPE:arp], treatment=[immediate=[FabricIngress.clone_to_cpu()]]
    ADDED, ..., table=FabricIngress.acl, priority=40000, selector=[ETH_TYPE:ipv6, IP_PROTO:58, ICMPV6_TYPE:135], treatment=[immediate=[FabricIngress.clone_to_cpu()]]
    ADDED, ..., table=FabricIngress.acl, priority=40000, selector=[ETH_TYPE:lldp], treatment=[immediate=[FabricIngress.clone_to_cpu()]]
    ADDED, ..., table=FabricIngress.acl, priority=40000, selector=[ETH_TYPE:bddp], treatment=[immediate=[FabricIngress.clone_to_cpu()]]
```

These flow rules are the result of the translation of flow objectives generated
automatically for each device by the `hostprovider` and `lldpprovider` apps.

`hostprovider` app provides host discovery capabilities by sniffing ARP
(`selector=[ETH_TYPE:arp]`) and NDP packets (`selector=[ETH_TYPE:ipv6,
IP_PROTO:58, ICMPV6_TYPE:...]`), which are cloned to the controller
(`treatment=[immediate=[FabricIngress.clone_to_cpu()]]`). Similarly,
`lldpprovider` generates flow objectives to sniff LLDP and BBDP packets
(`selector=[ETH_TYPE:lldp]` and `selector=[ETH_TYPE:bbdp]`) periodically emitted
on all devices' ports as P4Runtime packet-outs, allowing automatic link
discovery.

Flow objectives are translated to flow rules and groups by the pipeconf, which
provides a `Pipeliner` behavior implementation
([PipelinerImpl.java](app/src/main/java/org/p4/p4d2/tutorial/pipeconf/PipelinerImpl.java)).
Moreover, these flow rules specify a match key by using ONOS standard/known
header fields (or "Criteria" using ONOS terminology), such as `ETH_TYPE`,
`ICMPV6_TYPE`, etc.  These types are mapped to P4 program/P4Info-specific match
field by the same pipeline interpreter modified before
[InterpreterImpl.java](app/src/main/java/org/p4/p4d2/tutorial/pipeconf/InterpreterImpl.java)
(look for method `mapCriterionType`)

To show all groups installed so far, you can use the `groups` command. For
example to show groups on `leaf1`:
```
sdn@root > groups any device:leaf1
deviceId=device:leaf1, groupCount=1
   id=0x63, state=ADDED, type=CLONE, ..., appId=org.onosproject.core, referenceCount=0
       id=0x63, bucket=1, ..., weight=-1, actions=[OUTPUT:CONTROLLER]
```

In this case, you should see only one group of type `CLONE`, which is used to
clone packets to the controller (or to the CPU, using data plane terminology).
`CLONE` groups are the ONOS northbound abstraction equivalent to P4Runtime's
packet replication engine (PRE) `CloneSessionEntry`.


### Congratulations!

You have completed the first exercise. You can move to the next one, or check
the bonus steps below.

### Bonus: inspect BMv2 internal state

You can use the BMv2 CLI to dump all table entries currently
installed on the switch by ONOS. On a separate terminal window type:

```
$ bm-cli leaf1
```

This command (defined as a bash alias in the tutorial VM) will start the CLI for
the BMv2 switch in Mininet with name "leaf1".

On the BMv2 CLI prompt, type the following command:

```
RuntimeCmd: table_dump FabricIngress.acl
```

You should see exactly 5 entries, each one corresponding to a flow rule
in ONOS. For example, the flow rule matching on ARP packets should look
like this in the BMv2 CLI:

```
Dumping entry 0x4
Match key:
* standard_metadata.ingress_port       : TERNARY   0000 &&& 0000
* ethernet.dst_addr                    : TERNARY   000000000000 &&& 000000000000
* ethernet.src_addr                    : TERNARY   000000000000 &&& 000000000000
* ethernet.ether_type                  : TERNARY   0806 &&& ffff
* scalars.fabric_metadata_t.ip_proto   : TERNARY   00 &&& 00
* scalars.fabric_metadata_t.icmp_type  : TERNARY   00 &&& 00
* scalars.fabric_metadata_t.l4_src_port: TERNARY   0000 &&& 0000
* scalars.fabric_metadata_t.l4_dst_port: TERNARY   0000 &&& 0000
Priority: 2147443646
Action entry: FabricIngress.clone_to_cpu -
```

Note how the ONOS selector `[ETH_TYPE:arp]` has been translated to an entry
matching on the BMv2-specific header field `ethernet.ether_type`
(`hdr.ethernet.ether_type` in the P4 program and P4Info), while the bits of all
other fields are set as "don't care" (the mask is all zeros).

Similarly, you can use the `mc_dump` command to show the state of the BMv2
multicast engine, used to implement packet replication features such as clone
sessions. In this case, you should see only one entry for the CPU clone session:

```
RuntimeCmd: mc_dump
==========
MC ENTRIES
**********
mgrp(32867)
  -> (L1h=0, rid=1) -> (ports=[255], lags=[])
==========
...
```

255 is the CPU port set when running `stratum_bmv2` in Mininet
([mininet/topo.py](mininet/topo.py)), and when writing the clone session in ONOS
([AppConstants.java](app/src/main/java/org/p4/p4d2/tutorial/AppConstants.java)).

The BMv2 CLI is a powerful tool to debug the state of a BMv2 switch. Type `help`
to show a list of possible commands. This CLI provides also auto-completion when
pressing the `tab` key.

**Warning:** the BMv2 CLI uses the Thrift server exposed by `simple_switch`.
Because the capabilities of the Thrift server overlap with those of the
gRPC/P4Runtime one provided by Stratum (e.g. a table management API is exposed
by both), there could be inconsistency issues when using both to write state to
the switch. As such, **we recommend using this CLI only to read state**.


