## Exercise 4: Segment Routing v6 (SRv6)

In this exercise, you will be be implementing a simplified version of segment routing,
a source routing method that steers traffic though a specified set of nodes.

This exercise is based on an IETF draft specification called SRv6, which uses
IPv6 packets to frame traffic that follows an SRv6 policy. SRv6 packets use the
IPv6 routing header, and they can either encapsulate IPv6 (or IPv4) packets entirely
or they can just inject an IPv6 routing header into an existing IPv6 packet.

The IPv6 routing header looks as follows:
```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Last Entry   |     Flags     |              Tag              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[0] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                                                               |
                                  ...
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[n] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The **Next Header** field is the type of either the next IPv6 header or the payload.

For SRv6, the **Routing Type** is 4.

**Segments Left** points to the index of the current segment in the segment list. In properly
formed SRv6 packets, the IPv6 destination address equals `Segment List[Segments Left]`. The
original IPv6 address should be `Segment List[0]` in our exercise so that traffic is routed
to the correct destination eventually.

**Last Entry** is the index of the last entry in the segment list.

Note: This means it should
be one less than the length of the list. (In the example above, the list is `n+1` entries and last
entry should be `n`.)

Finally, the **Segment List** is a reverse-sorted list of IPv6 addresses to be traversed in a
specific SRv6 policy. The last entry in the list is the first segment in the SRv6 policy. The
list is not typically mutated; the entire header is inserted or removed as a whole.

To keep things simple and because we are already using IPv6, your solution will just
be adding the routing header to the existing IPv6 packet. (We won't be embedding entire packets
inside of new IPv6 packets with a SRv6 policy, although the spec allows it and there are
valid use cases for doing so.)

As you may have already noticed, SRv6 uses IPv6 addresses to identify segments in a policy.
While the format of the addresses is the same as IPv6, the address space is typically different
from the space used for switch's internal IPv6 addresses. The format of the address also differs.
A typical IPv6 unicast address is broken into a network prefix and host identifier pieces, and a subnet mask
is used to delineate the boundary between the two. A typical SRv6 segment identifier (SID) is broken into
a locator, a function identifier, and optionally, function arguments. The locator must be routable,
which enables both SRv6-enable and unaware nodes to participate in forwarding.

HINT: Due to optional arguments, longest prefix match on the 128-bit SID is preferred to exact match.

There are three types of nodes of interest in a segment routed network:

1. Source Node - the node (either host or switch) that injects the SRv6 policy.
2. Transit Node - a node that forwards an SRv6 packet, but is not the destination
for the traffic
3. Endpoint Node - a participating waypoint in an SRv6 policy that will modify the
SRv6 header and perform a specified function

In our implementation, we simplify these types into two roles:
- Endpoint Node - for traffic to the switch's SID, update the SRv6 header (decrement segments
left), set the IPv6 destination address to the next segment, and forward the packets 
("End" behavior). For simplicity, we will always remove the SRv6 header on the penultimate
segment in the policy (called Penultimate Segment Pop or PSP in the spec).


- Transit Node - by default, forward traffic normally if it is not destined for the
switch's IP address or its SID ("T" behavior). Allow the control plane to add rules
to inject SRv6 policy for traffic destined to specific IPv6 addresses ("T.Insert"
behavior).

For more details, you can read the draft specification here:
https://tools.ietf.org/id/draft-filsfils-spring-srv6-network-programming-06.html

### Step 1: adding tables for SRv6

We have already defined the SRv6 header as well as included the logic for parsing the header
in `header.p4` and `parser.p4` respectively.

The next step is to add two tables to `main.p4` for each of the two roles specified above.
In addition to the tables, you will also need to write the action for the endpoint node table
(otherwise called the "My SID" table); we have provided the `t_insert` actions for policies of
length 2 and 3, which should be sufficient to get you started.

Once you've finished that, you will need to apply the tables in the `apply` block at the bottom
of your `FabricEngress` section. You will want to apply the tables after checking that the L2
destination address matches the switch's, and before the L3 table is applied (because you'll
want to use the same routing entries to forward traffic after the SRv6 policy is applied). You
can also apply the PSP behavior as part of your apply logic because we will always be applying it
if we are the penultimate SID.

### Step 2: testing the pipeline with Packet Test Framework (PTF)

FIXME: Testing with PTF
In this exercise, you will be modifying tests in [srv6.py](ptf/tests/srv6.py) to verify the SRv6
behavior of the pipeline.

Now we can try the PTF test for routing without any modification.

To run the test for routing, enter `ptf` directory and use following command:
```bash
make srv6
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

# FIXME 

Now we have shown that we can install basic rules and pass traffic using BMv2.

Some troubleshooting tips:
 - Log for PTF is located at `tutorial/ptf/ptf.log`
 - Pcap file of PTF is located at `tutorial/ptf/ptf.pcap`, you can find what we sent and what we received.

----

### Step 3: building the ONOS App

For the ONOS application, you will need to update `Srv6Component.java` in the following ways:

- Complete the `setUpMySidTable` method which will insert an entry into the My SID table that matches the
specified device's SID and performs the `end` action. This function is called whenever a new devices
is connected.

- Complete the `insertSrv6InsertRule` function, which creates a `t_insert` rule along for the provided
SRv6 policy. This function is called by the `srv6-insert` CLI command.

- Complete the `clearSrv6InsertRules`, which is called by the `srv6-clear` CLI command.

Once you are finished, you should rebuild and reload your app. This will also rebuild and republish any
changes to your P4 code and the ONOS pipeconf.
As with previous exercises, you can use the following command:
                       
```bash
$ make app-reload
```

### Step 4: inserting an SRv6 policy

To add new SRv6 policies, you should use the `srv6-insert` command.

```
onos> srv6-insert <device ID> <segment list>
```

For example, to add a policy that forwards traffic between h1a and h3 though spine1 and leaf2, you can use
the following command:

```
onos> srv6-insert device:bmv2:leaf1 3:201:2:: 3:102:2:: 2001:1:3::1
```

This command will match on traffic to the last segment on the specified device (e.g. match `2001:1:3::1` on
`leaf1`). You can update the command to specific more specific match criteria as extra credit.

You can confirm that your rule has been added using a variant of the following:

(HINT: Make sure to update the tableId to match the one in your P4 program.)
```
FIXME
sdn@root > flows any device:bmv2:leaf1 | grep tableId=FabricIngress.srv6_transit
    id=c40000e582112b, state=ADDED, bytes=0, packets=0, duration=169, liveType=UNKNOWN, priority=10, tableId=FabricIngress.srv6_transit, appId=org.p4.srv6-tutorial.srv6, selector=[hdr.ipv6.dst_addr=0x20010001000300000000000000000001/128], treatment=DefaultTrafficTreatment{immediate=[FabricIngress.srv6_t_insert_3(s3=0x20010001000300000000000000000001, s1=0x20020000000000000000000000000001, s2=0x20010000000000000000000000000002)], deferred=[], transition=None, meter=[], cleared=false, StatTrigger=null, metadata=null}
```

### Step 5: testing with Mininet

FIXME: Testing with Mininet

### Notes

If you need to remove your SRv6 policies, you can use the `srv6-clear` command to clear all SRv6 policies
from a specific device. For example to remove flows from `leaf1`, use this command:

```
onos> srv6-clear device:bmv2:leaf1 
```


