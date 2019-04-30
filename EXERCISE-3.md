## Exercise 3: IPv6 routing

In this exercise, you will be modifying the P4 program and ONOS app to add
support for IPv6-based (L3) routing between all hosts connected to the fabric,
with support for ECMP to forward traffic across the spines.

## Overview

### Requirements

At this stage, we want our fabric to behave like a standard IP fabric, with
switches behaving as routers. As such, the following requirements should be
satisfied by
our fabric:

* Leaf interfaces should be assigned with an IPv6 address (the gateway address) 
  and a a MAC address that we will call `myStationMac`;
* Leaf switches should be able to handle NDP Neighbor Solicitation (NS)
  messages sent by hosts to resolve the MAC address associated with the
  switch interface/gateway IPv6 addresses, by replying with NDP Neighbor
  Advertisement (NA) informing hosts of their `myStationMac` address;
* Packets received with Ethernet destination `myStationMac` should be processed
  through the routing pipeline, otherwise the bridging one;
* When routing, the P4 program should look at the IPv6 destination address, if a
  matching entry is found, the packet should be forwarded to a given next hop
  and the packet Ethernet addresses modified accordingly (source set to 
  `myStationMac` and destination to the next hop one);
* When routing packets to a different leaf across the spines, leaf switches
  should be able to use ECMP do distribute traffic.

### Configuration

The [netcfg.json](netcfg.json) file includes a special configuration for each
device named `srv6DeviceConfig`, this block defines 3 values:

 * `myStationMac`: MAC address associated with the device, i.e., the router MAC
   address;
 * `mySid`: the SRv6 segment ID of the device, used in the next exercise.
 * `isSpine`: a boolean flag whether the device should be considered as a spine
   switch.

Moreover, the [netcfg.json](netcfg.json) file also includes a list of interfaces
with an IPv6 prefix assigned to them (look under the `ports` section of the
file). The same IPv6 addresses are used in the Mininet topology script
[topo.py](mininet/topo.py).

### Try pinging hosts in different subnets

Similarly to the previous exercise, let's start by using Mininet to verify that
pinging hosts on different subnets it does NOT work. It will be your task to
make it work.

On the Mininet CLI:

```
mininet> h2 ping h3
PING 2001:2:3::1(2001:2:3::1) 56 data bytes
From 2001:1:2::1 icmp_seq=1 Destination unreachable: Address unreachable
From 2001:1:2::1 icmp_seq=2 Destination unreachable: Address unreachable
From 2001:1:2::1 icmp_seq=3 Destination unreachable: Address unreachable
...
```

If you check the ONOS log, you will notice that `h2` has been discovered:

```
INFO  [L2BridgingComponent] HOST_ADDED event! host=00:00:00:00:00:20/None, deviceId=device:leaf1, port=6
INFO  [L2BridgingComponent] Adding L2 unicast rule on device:leaf1 for host 00:00:00:00:00:20/None (port 6)...
```

That's because `h2` sends NDP NS messages to resolve the MAC address of its
gateway (`2001:1:2::ff` as configured in [topo.py](mininet/topo.py)).

Indeed, we can check the IPv6 neighbor table for `h2` to see that the resolution
has failed:

```
mininet> h2 ip -6 n
2001:1:2::ff dev h2-eth0  FAILED
```

### P4-based generation of NDP messages

The starter P4 code already provides a table `ndp_reply_table` and action
`ndp_ns_to_na(mac_addr_t target_mac)` to reply to NDP NS messages sent by
hosts to resolve the MAC address of the switch interface/gateway IPV6 addresses.

The table essentially provides a mapping between an IPv6 addresses and its
corresponding MAC address() defined as the action parameter). The action
implementation transforms the same NDP NS packet into an NA one with the given
target MAC address.

The ONOS app already provides a component
[NdpReplyComponent.java](app/src/main/java/org/p4/p4d2/tutorial/NdpReplyComponent.java)
responsible of populating the `ndp_reply_table` with all interface IPv6
addresses defined in the [netcfg.json](netcfg.json) and using `myStationMac` as
the target MAC address.

The component is currently disabled, you will need to enable it in the next
steps. But first, let's focus on the P4 program.

## Exercise steps

### 1. Modify P4 program

The first step will be to add new tables to `main.p4`.

#### LPM IPv6 routing table

The main table for this exercise will be an L3 table that matches on destination
IPv6 address. You should create a table that performs the longest prefix match
on the destination address and performs the required packet transformations.

The action is not defined in this exercise as it was for Exercise 2. This action
should:

1. Update the source Ethernet address to `myStationMac` (passed as an action 
   argument);
2. Set the destination Ethernet to the next hop's address (passed as an action
   argument);
3. Decrement the IPv6 `hop_limit`.

This L3 table and action should provide a mapping between a given IPv6 prefix
and a next hop MAC address. In our solution (and hence in the PTF starter code
and ONOS app), we re-use the L2 table defined in the previous exercise to
provide a mapping between the next hop MAC address and an output port. If you
want to apply the same solution, make sure to call the L3 table before the L2
one in the `apply` block.

Moreover, we will want to drop the packet when the IPv6 hop limit reaches 0.
This can be accomplished by inserting logic in the `apply` that inspects the
field after applying your L3 table.

At this point, your pipeline should properly match, transform, and forward IPv6
packets.

**Note:** For simplicity, we are using a global routing table. If you would like
to segment your routing table in virtual ones (i.e. using a VRF ID), you can
tackle this as extra credit.

#### "My Station" table

You may realize that at this point that the switch will perform IPv6 routing
indiscriminately, which is technically incorrect. The switch should only route
Ethernet frames that are destined for the router's Ethernet address
(`myStationMac`).

To address this issue, you will need to create a table that will match the
destination Ethernet address and mark the packet for routing if there is a
match. We call this the "My Station" table.

You are free to use a specific action or metadata to carry this information, or
for simplicity, you can use `NoAction` and check for a hit in this table in your
`apply` block. Remember to update your `apply` block after creating this table.

#### Adding support for ECMP with action selectors

The last modification that you will make to the pipeline is to add an
`action_selector` that will hash traffic between the different possible paths.
In our leaf-spine topology, we have an equal-cost path for each spine for every
leaf pair, and we want to be able to take advantage of that.

We have already defined the P4 `ecmp_selector` for you, but you will need to add
the selector to your L3 table. You will also need to add the selector fields as
match keys.

For IPv6 traffic, you will need to include the source and destination IPv6
addresses as well as the IPv6 flow label as part of the ECMP hash, but you are
free to include other parts of the packet header if you would like. For example,
you could include the rest of the 5-tuple (i.e. L4 proto and ports); the L4
ports are parsed into `fabric_metadata` if would like to use them. For more
details on the required fields for hashing IPv6 traffic, see RFC6438.

You can compile the program using `make p4` from the `tutorial` directory.
Make sure to address any compiler errors before continuing.

At this point, our P4 pipeline should be ready for testing.

### 2. Run PTF tests

Tests for the IPv6 routing behavior are located in `ptf/tests/routing.py`. Open
that file up and modify wherever requested (look for `TODO EXERCISE 3`).

To run all tests for this exercise:

    cd ptf
    make routing

This command will run all tests in the `routing` group (i.e. the content of
`ptf/tests/routing.py`). To run a specific test case you can use:

    make <PYTHON MODULE>.<TEST CASE NAME>

For example:

    make bridging.IPv6RoutingTest

#### Check for regressions

To make sures the new changes are not breaking other features, make sure to run
tests of the previous exercises as well.

    make packetio
    make bridging
    make routing

If all tests succeed, congratulations! You can move to the next step.

### 3. Modify ONOS app

The last part of the exercise is to update the starter code for routing
component of our ONOS app, located here:
`app/src/main/java/org/p4/p4d2/tutorial/Ipv6RoutingComponent.java`

This session will focus on adding support for routing of IPv6 packets.

First is to modify the `setUpMyStationTable` method to insert a rule that
matches the router's Ethernet address(`myStationMac` from network config) and insert it into your my station table.

This method will be called when a device is added and the device is available, and get device mac address
from network configuration. (See `InternalDeviceListener` class)

After completed the method and reload the application (`make app-build app-reload`),
you should be able to get related flows from ONOS command line:

```
sdn@root > flows -s
... skip ...
    ADDED, bytes=0, packets=0, table=<Table Name>, priority=10, selector=[<Match field name (dst mac)>=<Router Mac>], treatment=[immediate=[<Action Name>]]
    ADDED, bytes=0, packets=0, table=<Table Name>, priority=10, selector=[<Match field name (dst mac)>=<Router Mac>], treatment=[immediate=[<Action Name>]]
    ADDED, bytes=0, packets=0, table=<Table Name>, priority=10, selector=[<Match field name (dst mac)>=<Router Mac>], treatment=[immediate=[<Action Name>]]
    ADDED, bytes=0, packets=0, table=<Table Name>, priority=10, selector=[<Match field name (dst mac)>=<Router Mac>], treatment=[immediate=[<Action Name>]]
... skip ...
```

----

Second, complete three method below to provide routing with ECMP.

These three methods will be called when a link or a host which connected to this device is up. 

#### The createNextHopGroup method

The `createNextHopGroup` creates an group with given group ID and collection of next hop mac address.

An packet can be route to one or more next hop(s), when a routing entry uses this group, 
the device will choose a group member(action) which based on implementation of `action selector` in previous section.

Once a group member has selected, the device will perform the action, which sets the next hop mac address in this case.

You goal is to create members(actions) for this group to set the next hop address to the packet.

The flows will be looks like:

```
onos> groups
... skip ...
deviceId=device:bmv2:leaf1, groupCount=7
   # This is a group which set next hop to spines
   id=0xec3b0000, state=ADDED, type=SELECT, bytes=0, packets=0, appId=org.p4.srv6-tutorial, referenceCount=0
       id=0xec3b0000, bucket=1, bytes=0, packets=0, weight=1, actions=[FabricIngress.set_l2_next_hop(dmac=0xbb00000002)]
       id=0xec3b0000, bucket=2, bytes=0, packets=0, weight=1, actions=[FabricIngress.set_l2_next_hop(dmac=0xbb00000001)]
   # This is a group which set next hop to the host (host h1a)
   id=0x1a, state=ADDED, type=SELECT, bytes=0, packets=0, appId=org.p4.srv6-tutorial, referenceCount=0
       id=0x1a, bucket=1, bytes=0, packets=0, weight=1, actions=[FabricIngress.set_l2_next_hop(dmac=0x1a)]
... skip ...
```

#### The createRoutingRule method

The `createRoutingRule` creates the routing rule with given IPv6 prefix and group ID we used from previous method.

```
onos> flows -s
deviceId=device:bmv2:leaf1, flowRuleCount=25
... skip ...
# These are flows which sends packet through spines
    ADDED, bytes=0, packets=0, table=<L3 Table name>, priority=10, selector=[<IP prefix field>=0x20010001000300000000000000000000/64], treatment=[immediate=[GROUP:0xec3b0000]]
    ADDED, bytes=0, packets=0, table=<L3 Table name>, priority=10, selector=[<IP prefix field>=0x20010001000400000000000000000000/64], treatment=[immediate=[GROUP:0xec3b0000]]
# A flow which route a packet to host
    ADDED, bytes=0, packets=0, table=<L3 Table name>, priority=10, selector=[<IP prefix field>=0x2001000100010000000000000000000a/128], treatment=[immediate=[GROUP:0x1a]]
... skip ...
```

#### The createNextHopRule method

The `createNextHopRule` method which creates L2 rules for next hop. This method is used to set output port according to 
the destination address. We already have similar method in `L2BridgingComponent` (see `learnHost` method).
This method is called when two device(switch) connected, and create L2 rules between devices. We don't handle L2 rule 
for hosts since we already installed necessary rules for host in `L2BridgingComponent`.

----

After the app completed and reload to ONOS, you should be able to ping between different hosts from multiple subnet.

*Note:* The ONOS must learn host IP address first to install necessary rules. To check which hosts are learnt by ONOS 
simply use `hosts` command in ONOS CLI (or `hosts -s` for simple one).

There should be six hosts:
```
onos> hosts -s
id=00:00:00:00:00:1A/None, mac=00:00:00:00:00:1A, locations=[device:bmv2:leaf1/3], vlan=None, ip(s)=[2001:1:1::a]
id=00:00:00:00:00:1B/None, mac=00:00:00:00:00:1B, locations=[device:bmv2:leaf1/4], vlan=None, ip(s)=[2001:1:1::b]
id=00:00:00:00:00:1C/None, mac=00:00:00:00:00:1C, locations=[device:bmv2:leaf1/5], vlan=None, ip(s)=[2001:1:1::c]
id=00:00:00:00:00:20/None, mac=00:00:00:00:00:20, locations=[device:bmv2:leaf1/6], vlan=None, ip(s)=[2001:1:2::1]
id=00:00:00:00:00:30/None, mac=00:00:00:00:00:30, locations=[device:bmv2:leaf2/3], vlan=None, ip(s)=[2001:1:3::1]
id=00:00:00:00:00:40/None, mac=00:00:00:00:00:40, locations=[device:bmv2:leaf2/4], vlan=None, ip(s)=[2001:1:4::1]
```

**If you cannot find any host** from ONOS CLI, try use the host to send some NDP packet so the controller can learn it.
The easiest way to sent NDP packet is to ping another hosts with `ping` command, by default the host should send 
a *Router Solicitation* or *Neighbor Solicitation* message and those message will be captured by the controller.

Below is an example to send ping packet to `h1a` from `h2`.
```
mininet> h2 ping h1a
PING 2001:1:1::a(2001:1:1::a) 56 data bytes
64 bytes from 2001:1:1::a: icmp_seq=1 ttl=63 time=1.91 ms
64 bytes from 2001:1:1::a: icmp_seq=2 ttl=63 time=0.825 ms
64 bytes from 2001:1:1::a: icmp_seq=3 ttl=63 time=1.10 ms
64 bytes from 2001:1:1::a: icmp_seq=4 ttl=63 time=0.803 ms
64 bytes from 2001:1:1::a: icmp_seq=5 ttl=63 time=0.804 ms
64 bytes from 2001:1:1::a: icmp_seq=6 ttl=63 time=1.01 ms
```

### Congratulations!

You have completed the third exercise. You can now move to the next one.

