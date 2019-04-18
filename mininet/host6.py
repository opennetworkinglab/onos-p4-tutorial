#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from mininet.node import Host


class IPv6Host(Host):

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)

        def updateIP():
            return ipv6.split('/')[0]
        self.defaultIntf().updateIP = updateIP

    def terminate(self):
        # self.cmd( 'sysctl -w net.ipv6.conf.all.forwarding=0' )
        super(IPv6Host, self).terminate()


class SRv6Host(IPv6Host):

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        # Enable SRv6
        self.cmd('sysctl -w net.ipv6.conf.all.seg6_enabled=1')
        self.cmd('sysctl -w net.ipv6.conf.%s.seg6_enabled=1' % self.defaultIntf())
