# Exercise 2: Bridging

In this exercise, you will be modifying the P4 program and ONOS app to add
support for Ethernet (L2) bridging for hosts connected to the same leaf switch
and belonging to the same subnet.

## Overview

The ONOS app assumes that hosts of a given subnet are all connected to the same
leaf, and two interfaces of two different leaves cannot be configured with the
same IPv6 subnet. In other words, L2 bridging is allowed only for hosts
connected to the same leaf.

The Mininet script [topo.py](mininet/topo.py) used in this tutorial defines 4
subnets:

* `2001:1:1::/64` with 3 hosts connected to `leaf1` (`h1a`, `h1b`, and `h1c`)
* `2001:1:2::/64` with 1 hosts connected to `leaf1` (`h2`)
* `2001:2:3::/64` with 1 hosts connected to `leaf2` (`h3`)
* `2001:2:4::/64` with 1 hosts connected to `leaf2` (`h4`)

The same IPv6 prefixes are defined in the [netcfg.json](netcfg.json) file and
are used to provide interface configuration to ONOS.

### Try pinging hosts

As a start, try to use Mininet to ping any two hosts of the first subnet. It
should not work, since you have not implemented any bridging logic in P4 nor
installed table entries for it.

On the Mininet CLI:

```
mininet> h1a ping h1b
PING 2001:1:1::b(2001:1:1::b) 56 data bytes
From 2001:1:1::a icmp_seq=1 Destination unreachable: Address unreachable
From 2001:1:1::a icmp_seq=2 Destination unreachable: Address unreachable
From 2001:1:1::a icmp_seq=3 Destination unreachable: Address unreachable
...
```

However, since `h1a` is expected to generate NDP Neighbor Solicitation (NS)
messages to discover the Ethernet address of `h1b`, and since we have activated
the `hostprovider` app in the previous exercise (remember the ACL flow rules
cloning NDP packets to the CPU), we expect ONOS to discover host `h1a`. To check
that, use the ONOS CLI:

```
onos> hosts -s
id=00:00:00:00:00:1A/None, mac=00:00:00:00:00:1A, locations=[device:leaf1/3], vlan=None, ip(s)=[2001:1:1::a]
```

The host MAC address, as well as the location, and the IPv6 address have been
learned by the `hostprovider` app by sniffing the NDP NS packet.

## Exercise steps

### 1. Modify P4 program

In the ingress pipeline of `main.p4`, we have already defined some actions that
you will need to complete the exercise -- namely `set_output_port` for unicast
packets and `set_multicast_group` for packets that will be sent out of multiple
ports, such as NDP NS messages. Multicast groups will be created by the ONOS app
later. What is missing is a table that uses these actions.

The first step will be to create an L2 table with match on destination Ethernet
address and actions mentioned above. There are two types of destination
addresses that you will need to support:

1. **Broadcast/multicast** entries: used replicate NDP Neighbor Solicitation
(NS) messages to all host facing ports;

2. **Unicast** entries: which will be filled in by the control plane (i.e. ONOS
app) when hosts are discovered.

Unlike ARP messages which are broadcasted to Ethernet destination address
`FF:FF:FF:FF:FF:FF`, NDP messages use IPv6 broadcast/multicast packets that are
sent to special Ethernet addresses specified by RFC2464. These destination
addresses are prefixed with `33:33` and the last four octets are the last four
octets of the IPv6 destination multicast address. The most straightforward way
of matching on such IPv6 broadcast/multicast packets, without digging in the
details of RFC2464, is to use a ternary match on `33:33:**:**:**:**`, where `*`
means "don't care".

**Thought experiment**: What type of match key will you use for this table
(e.g. exact, LPM, ternary)? Will exact match work for multicast entries? Are
there downsides to using non-exact for unicast entries? Our solution uses two L2
tables for each type of entry (exact for unicast, and ternary for multicast),
but you can choose a different approach.

**Note**: To keep things simple, we won't be using VLANs to segment our L2
domains, but you can also add support for VLANs as an extra credit exercise.

After creating your L2 table(s), you will need to apply these tables from the
`apply` block area of the ingress pipeline (`FabricIngress`).

When done, you can compile the program using `make p4` from the `tutorial`
directory. Make sure to address any compiler errors before continuing.

At this point, your P4 pipeline should be ready for testing.

### 2. Run PTF tests

Tests for the L2 bridging behavior are located in `ptf/tests/bridging.py`. Open
that file up and modify wherever requested (look for `TODO EXERCISE 2`).

To run all tests for this exercise:

    cd ptf
    make bridging

This command will run all tests in the `bridging` group (i.e. the content of
`ptf/tests/bridging.py`). To run a specific test case you can use:

    make <PYTHON MODULE>.<TEST CASE NAME>

For example:

    make bridging.ArpNdpRequestWithCloneTest

**Check for regressions**

To make sure the new changes are not breaking other features, make sure to run
tests of the previous exercises as well.

    make packetio
    make bridging

If all tests succeed, congratulations! You can move to the next step.

### 3. Modify ONOS app

The next step will be to modify the ONOS app to control the L2 bridging parts of
the P4 program modified before.

The source code that you will need to modify is located here:
`app/src/main/java/org/p4/p4d2/tutorial/L2BridgingComponent.java`

Modify the code wherever requested (look for `TODO EXERCISE 2`).

#### Complete methods implementation to insert L2 flow rules

This app component defines two event listener located at the bottom of the
`L2BridgingComponent` class, `InternalDeviceListener` for device events (e.g.
connection of a new switch) and `InternalHostListener` for host events (e.g. new
host discovered). These listeners in turn call methods like:

* `setUpDevice()`: responsible for creating a multicast group for all host-facing
  ports and inserting flow rules for broadcast/multicast packets such as ARP and
  NDP messages;

* `learnHost()`: responsible for inserting unicast L2 entries based on the
  discovered host location.

To support reloading the app implementation, these methods are also called at
component activation for all devices and hosts known by ONOS at the time of
activation (look for methods `activate()` and `setUpAllDevices()`).

To keep things simple, our broadcast domain will be restricted to a single
device, i.e. we allow packet replication only for ports of the same leaf switch.
As such, we can exclude ports going to the spines from the multicast group. To
determine whether a port is expected to be facing hosts or not, we look at the
interface configuration in [netcfg.json](netcfg.json) file (look for the `ports`
section of the JSON file).

The starter code already provides an implementation of the method
`insertMulticastGroup()`, you are required to complete the implementation of two
other methods, `insertMulticastFlowRules()` and `learnHost()`.

#### Enable component

Once you're confident your solution to the previous step should work, before
building and reloading the app, remember to enable the component by setting the
`enabled` flag on top of the class definition:

```
/**
 * App component that configures devices to provide L2 bridging capabilities.
 */
@Component(
        immediate = true,
        enabled = true
)
public class L2BridgingComponent {
    ...
```

#### Build and reload the app

Use the following commands to build and reload your app while ONOS is running:

```
$ make app-build
$ make app-reload
```

When building the app, the modified P4 compiler outputs (`bmv2.json` and
`p4info.txt`) will be packaged together along with the Java classes. After
reloading the app, you should see messages signaling that a new pipeline
configuration has been set and the `L2BridgingComponent` has been activated:

```
INFO  [PipeconfLoader] Detected updated pipeconf fingerprint, reloading...
INFO  [PiPipeconfManager] Unregistered pipeconf: org.p4.srv6-tutorial (fingerprint=2e:39:f0:81:cd:a3:76:20)
INFO  [PipeconfLoader] Found 1 outdated drivers for pipeconf 'org.p4.srv6-tutorial', removing...
INFO  [PiPipeconfManager] New pipeconf registered: org.p4.srv6-tutorial (fingerprint=2e:39:f0:81:1f:37:e6:82)
INFO  [PipelineConfigClientImpl] Setting pipeline config for device:leaf1 to org.p4.srv6-tutorial...
...
INFO  [MainComponent] Waiting to remove flows and groups from previous execution of org.p4.srv6-tutorial..
...
INFO  [MainComponent] Started
INFO  [L2BridgingComponent] Started
...
INFO  [L2BridgingComponent] *** L2 BRIDGING - Starting initial set up for device:leaf1...
INFO  [L2BridgingComponent] Adding L2 multicast group with 4 ports on device:leaf1...
INFO  [L2BridgingComponent] Adding L2 multicast rules on device:leaf1...
INFO  [L2BridgingComponent] Adding L2 unicast rule on device:leaf1 for host 00:00:00:00:00:1A/None (port 3)...
...
```

#### Understanding ONOS error logs

Before trying your solution in Mininet, it's worth looking at the ONOS log for
possible errors. There are mainly 2 types of errors that you might see when
reloading the app:

1. Write errors like removing a nonexistent entity or inserting one that
   already exists, such as:

    ```
    WARN  [WriteResponseImpl] Unable to DELETE PRE entry on device...: NOT_FOUND Multicast group does not exist ...
    WARN  [WriteResponseImpl] Unable to INSERT table entry on device...: ALREADY_EXIST Match entry exists, use MODIFY if you wish to change action ...
    ```
    
    These are usually transient errors and **you should not worry about it**.
    They describe a temporary inconsistency of the ONOS-internal device state,
    which should be soon recovered by a periodic reconciliation mechanism.
    Indeed, the ONOS core periodically polls the device state to make sure it's
    internal representation is accurate, while writing any pending modifications
    to the device, solving these errors.
    
    Otherwise, if you see them appearing periodically (every 3-4 seconds), it
    means the reconciliation process is not working and something else is wrong.
    Try re-loading the app (`make app-reload`), if it doesn't work, check with
    the instructors.
    
2. Translation errors, signifying that ONOS is not able to translate the flow
   rules (or groups) generated by apps, to a representation that is compatible
   with your P4Info. For example:

    ```
    WARN  [P4RuntimeFlowRuleProgrammable] Unable to translate flow rule for pipeconf 'org.p4.srv6-tutorial':...
    ```
   
    **Read carefully the error message and make changes to the app as needed.**
    Chances are that you are using a table, match field, or action name that
    does not exist in your P4Info. Check your P4Info file, modify, and reload the
    app (`make app-build && make app-reload`).

### 4. Test L2 bridging on Mininet

Now that the app has been modified and reloaded, and the ONOS log is free
of potentially harmful errors, you should be able to repeat the same ping
test done at the beginning of the exercise and expect it to work:

```
mininet> h1a ping h1b
PING 2001:1:1::b(2001:1:1::b) 56 data bytes
64 bytes from 2001:1:1::b: icmp_seq=2 ttl=64 time=0.580 ms
64 bytes from 2001:1:1::b: icmp_seq=3 ttl=64 time=0.483 ms
64 bytes from 2001:1:1::b: icmp_seq=4 ttl=64 time=0.484 ms
...
```

Check the ONOS log, you should see messages related to the discovery of host
`h1b` who is now receiving NDP NS messages from `h1a` and replying with NDP NA
ones to them (remember that `h1a` was already discovered at the beginning of
the exercise):

```
INFO  [L2BridgingComponent] HOST_ADDED event! host=00:00:00:00:00:1B/None, deviceId=device:leaf1, port=4
INFO  [L2BridgingComponent] Adding L2 unicast rule on device:leaf1 for host 00:00:00:00:00:1B/None (port 4)...
```

#### Troubleshooting

If ping is not working, here are few steps you can take to troubleshoot your
network:

1. **Check that all flow rules and groups have been written successfully to the
   device.** Using ONOS CLI commands such as `flows -s any device:leaf1` and
   `groups any device:leaf1`, verify that all flows and groups are in state
   `ADDED`. If you see other states such as `PENDING_ADD`, check the ONOS log
   for possible errors with writing those entries to the device. You can also
   use the ONOS web UI to check flows and group state.

2. **Use table counters to verify that tables are being hit as expected.**
   If you don't already have direct counters defined for your L2 table(s),
   modify the P4 program to add some, build and reload the app (`make app-build
   && make app-reload`). ONOS should automatically detect that and poll counters
   every 3-4 seconds (the same period for the reconciliation process). To check
   their values, you can either use the ONOS CLI (`flows -s any device:leaf1`)
   or the web UI.

3. **Check again the PTF tests** and make sure you are creating similar flow
   rules in the `L2BridgingComponent.java`. Do you notice any difference?

4. **Look at the BMv2 logs for possible errors.** Check files in
   `/tmp/bmv2-<SW-NAME>-log` or use the `bm-log <SW-NAME>` bash command.

5. If here and still not working, **reach out to one of the instructors for
   assistance.**

## Congratulations

You have completed exercise 2! Now your fabric is capable of forwarding packets
between hosts in the same subnet and connected to the same leaf switch.
