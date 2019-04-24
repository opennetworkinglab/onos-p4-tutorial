#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class IPv6Node( Node ):

    def config( self, ipv6, ipv6_gw=None, **params ):
        super( IPv6Node, self).config( **params )
        self.cmd( 'ip -6 addr add %s dev %s' % ( ipv6, self.defaultIntf() ) )
        if ipv6_gw:
          self.cmd( 'ip -6 route add default via %s' % ( ipv6_gw ) )
        # Enable SRv6
        self.cmd( 'sysctl -w net.ipv6.conf.all.seg6_enabled=1' )
        self.cmd( 'sysctl -w net.ipv6.conf.%s.seg6_enabled=1' % self.defaultIntf() )
        # Enable forwarding on the router: 
        #self.cmd( 'sysctl -w net.ipv6.conf.all.forwarding=1' )

    def terminate( self ):
        #self.cmd( 'sysctl -w net.ipv6.conf.all.forwarding=0' )
        super( IPv6Node, self ).terminate()


class NetworkTopo( Topo ):
    "A LinuxRouter connecting three IP subnets"

    def build( self, **_opts ):
        s1 = self.addSwitch( 's1' )

        h1 = self.addHost( 'h1', cls=IPv6Node, ipv6='2001::1/64', ipv6_gw='2001::ff' )
        h2 = self.addHost( 'h2', cls=IPv6Node, ipv6='2001::2/64' )

        for h, s in [ (h1, s1), (h2, s1) ]:
            self.addLink( h, s )

def run():
    topo = NetworkTopo()
    net = Mininet( topo=topo )
    net.start()
    net['h1'].cmd( 'ip -6 addr add fd00:1::1 dev h1-eth0' )
    net['h2'].cmd( 'ip -6 addr add fd00:2::2 dev h2-eth0' )
    net['h1'].cmd( 'ip -6 route add fd00:2::2 encap seg6 mode inline segs 2001::2 dev h1-eth0' )
    net['h2'].cmd( 'ip -6 route add fd00:1::1 encap seg6 mode inline segs 2001::1 dev h2-eth0' )
    net['h1'].cmd( 'ip addr add 1.0.0.1 dev h1-eth0' )
    net['h2'].cmd( 'ip addr add 2.0.0.2 dev h2-eth0' )
    net['h1'].cmd( 'ip route add 2.0.0.2 encap seg6 mode encap segs 2001::2 dev h1-eth0 src 1.0.0.1' )
    net['h2'].cmd( 'ip route add 1.0.0.1 encap seg6 mode encap segs 2001::1 dev h2-eth0 src 2.0.0.2' )
    print 'h1 routing table:'
    print net['h1'].cmd( 'ip -6 route' )
    print 'h2 routing table:'
    print net['h2'].cmd( 'ip -6 route' )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

