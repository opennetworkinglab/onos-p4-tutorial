## Exercise 3: IPv6 routing

In this exercise, you will be adding some tables that will perform IPv6
routing of packets between the switches in your topology.

Adding tables for IPv6 routing
----

The first step will be to add the new tables to `main.p4`.

The main table for this exercise will be an L3 table that matches on destination
IPv6 address. You should create a table that performs the longest prefix match
on the destination address and performs the required packet transformations.

The action is not defined in this exercise as it was for Exercise 2. This action
should update the source Ethernet address to the router's address, set the destination
Ethernet to the next hop's address, and decrement the hop_limit.

After you create the table, you will need to apply the table in your `apply` block,
as you did in Exercise 2. At this point, your pipeline should properly match and
transform IPv6 packets.

**Note:** For simplicity, we are using a global routing table. If you would like
to segment your routing table in virtual tables (i.e. using a VRF ID), you can
tackle this as extra credit.

We will want to drop the packet when the IPv6 hop limit reaches 0. This can be
accomplished by inserting logic in the `apply` that inspects the field after applying
your L3 table.

You may realize that at this point that the switch will perform IPv6 routing
nondiscriminately, which is technically incorrect. The switch should only route
Ethernet frames that are destined for the router's Ethernet address.

To address this issue, you will need to create a table that will match the destination
Ethernet address and mark the packet for routing if there is a match.

You are free to use a specific action or metadata to carry this information, or
for simplicity, you can use `NoAction` and check for a hit in this table in your
`apply` block. Remember to update your `apply` block after creating this table.

The last modification that you will make to the pipeline is to add an `action_selector`
that will hash traffic between the different possible paths. In our leaf-spine topology,
we have an equal cost path for each spine for every leaf pair, and we want to be able
to take advantage of that.

We have already defined the `ecmp_selector` for you, but you will need to add the
selector to your L3 table. You will also need to add the selector fields as match keys.

For IPv6 traffic, you will need to include the source and destination IPv6 addresses as
well as the IPv6 flow label as part of the ECMP hash, but you are free to include other
parts of the packet header if you would like. For example, you could include the rest of
the 5-tuple (i.e. L4 proto and ports); the L4 port are parsed into fabric_metadata if
would like to use them. For more details on the required fields for hashing IPv6 traffic,
see RFC6438.

You can compile the program using `make p4` from the `tutorial` directory.
Make sure to address any compiler errors before continuing.

At this point, our P4 pipeline should be ready for testing.

Testing the pipeline with Packet Test Framework (PTF)
----

In this exercise,
you will be add test codes to [routing.py](ptf/tests/routing.py) to verify the routing
the behavior of the pipeline.

In the `IPv6RoutingTest` we test three different types of a packet: TCPv6, UDPv6, and ICMPv6

Those packets includes sample Ethernet, IPv6 headers and payload.
The test program will send packets to first port of test switch,
and we expect the switch routes the packet to the next hop, which performs actions below:

 1. Check if destination mac is the router mac(my station mac)
 2. Modify the mac address
    - source mac becomes to router mac(my station mac)
    - destination mac becomes to next hop mac address
 3. Decrement the TTL/HLIM of IP header
 4. Send the packet out to a port

Now we can try the PTF test for routing without any modification.

To run the test for routing, enter the `ptf` directory and use following command:

```bash
make routing
```

you should see message like:

```
========== EXPECTED ==========
.... Skip ....
========== RECEIVED ==========
0 total packets.
==============================
.... Skip ....
ATTENTION: SOME TESTS DID NOT PASS!!!
```

This message means there is no packet received by the test program.
We need to add some table entries and groups to make it works.

The first step is to program the table which checks the destination mac address.

To build the table entry, use `self.helper.build_table_entry` method and use `self.insert()`
to insert the table entry to the test device.

 - Hint: we can match destination mac of the packet directly in the table entry
 - Hint2: we can get destination mac of the packet with `pkt[Ether].dst`

After adding the code, the device should be able to process the packet with
destination mac address which equals to the router mac.

The test won't pass at this time. However, we can check trace log from BMv2 to see
how the packet been processed by the pipeline.

You can find trace log of Bmv2 switch here: `/tmp/bmv2-ptf.log`

In the trace log, you should be able to find messages like:

```
Applying table '<Table name>'
... skip ...
Table '<table name>': hit with handle xxxxxxxx
```

This means the packet sent by PTF hit the table we just created.

The next step is to add an ECMP group for routing, you can create and insert an
action profile group by using the code below:

```python
# Create an action profile group with a list of actions
action_prof_group = self.helper.build_act_prof_group(
    act_prof_name="<Action Profile Name>",
    group_id=<Group Id>,
    actions=[
        # List of tuples (action name, action param dict)
        ("<Action1 name>", {"<Param1 name>": <Param1 val>...}),
        ("<Action2 name>", {"<Param1 name>": <Param1 val>...}),
        ...
    ]
)
# Insert action profile group
self.insert(action_prof_group)
```

We can create a group with a single member which sets next hop address we expected (`next_hop_mac`)

After the group creation, we can add a table entry which points to this group.
To create a table entry which associate to a group, you can use the code below:

```python
table_entry = self.helper.build_table_entry(
    table_name="<Table Name>",
    match_fields={
        "<Match Field>": <Match Value>
    },
    group_id=<GROUP Id>
)
```

This table entry should be able to handle IPv6 routing, which matches the IPv6 prefix and set the next hop.

 - HINT: you can match destination IPv6 of the packet directly in the table entry
 - HINT2: you can get the destination IPv6 of the packet by `pkt[IPv6].dst`
 - HINT3: to match value with a prefix length (LPM), uses tuple `(value, prefix length)` as the value of match field

After this table entry and group installed, we should see the message from BMv2 trace log like:

```
Applying table '<Your routing table name>'
... skip ...
Table '<Your routing table name>': hit with handle xxxxxxxx
... skip ...
Action entry is <Action name> - <Action parameter>
```

The last thing we miss is the table which handles the packet with next hop destination mac.

We expected to receive the packet from second port of the switch.
This can be done by using the bridging table, see [EXERCISE-2.md](EXERCISE-2.md)

We should be able to see the following message if the test runs correctly:

```
routing.IPv6RoutingTest ... tcpv6 ... udpv6 ... icmpv6 ... ok

----------------------------------------------------------------------
Ran 1 test in 0.042s

OK
```

Now we have shown that we can install basic rules and pass traffic using BMv2.

Some troubleshooting tips:
 - Log for PTF is located at `tutorial/ptf/ptf.log`
 - Pcap file of PTF is located at `tutorial/ptf/ptf.pcap`, you can find what we sent and what we received.

Step 3: Developing the ONOS App
----

The last part of the exercise is to update the starter code for the routing exercise,
located here: `tutorial/app/src/main/java/org/p4/p4d2/tutorial/Ipv6RoutingComponent.java`.

The first step is to modify the `setUpMyStationTable` method to insert a rule that
matches the router's Ethernet address and insert it into your my station table.



FIXME WIP

This session will focus on adding support for routing of IPv6 packets between
different ToR switches.

Students will have to modify their P4 program and
ONOS app to handle IPv6 NDP Router Advertisement and Solicitation
messages, as well as programming of P4 table entries and action profile
groups to route packets across the fabric, using ECMP to distribute traffic
between multiple spines.