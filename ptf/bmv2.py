# Copyright 2018-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import logging
import os
import socket
import subprocess
import threading
import time
from contextlib import closing

BMV2_TARGET_EXE = 'simple_switch_grpc'
BMV2_RUNTIME_FILE_PATH_PREFIX = '/tmp/bmv2-ptf'
SWITCH_START_TIMEOUT = 5

logger = logging.getLogger("BMv2 switch")


def get_stratum_root():
    if 'STRATUM_ROOT' in os.environ:
        return os.environ['STRATUM_ROOT']
    else:
        raise Exception("STRATUM_ROOT env not defined")


def get_stratum_ld_path():
    if 'BMV2_INSTALL' in os.environ:
        return 'LD_LIBRARY_PATH=%s/lib' % os.environ['BMV2_INSTALL']
    else:
        raise Exception("BMV2_INSTALL env not defined")


STRATUM_ROOT = get_stratum_root()
STRATUM_BINARY = STRATUM_ROOT + '/bazel-bin/stratum/hal/bin/bmv2/stratum_bmv2'
STRATUM_CONFIG_DIR = '/tmp/stratum-bmv2'
STRATUM_LD_PATH = get_stratum_ld_path()
INITIAL_PIPELINE = STRATUM_ROOT + '/stratum/hal/bin/bmv2/dummy.json'


def check_bmv2_target(target):
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call([target, '--version'],
                                  stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return True
    except OSError:  # Target executable not found
        return False


def watchdog(sw):
    while True:
        if sw.bmv2popen is None:
            return
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            if s.connect_ex(('127.0.0.1', sw.grpc_port)) == 0:
                time.sleep(1)
            else:
                logger.error("%s process terminated!" % BMV2_TARGET_EXE)
                return


class Bmv2Switch:
    def __init__(self, device_id, port_map_path, grpc_port, cpu_port,
                 loglevel='warn', is_stratum=False, debugger=False):
        self.device_id = device_id
        self.port_map_path = port_map_path
        self.grpc_port = int(grpc_port)
        self.cpu_port = cpu_port
        self.loglevel = loglevel
        self.logfile = '%s.log' % BMV2_RUNTIME_FILE_PATH_PREFIX
        self.logfd = None
        self.bmv2popen = None
        self.is_stratum = is_stratum
        self.debugger = debugger

        if not is_stratum and not check_bmv2_target(BMV2_TARGET_EXE):
            raise Exception("%s executable not found" % BMV2_TARGET_EXE)

        if is_stratum and not os.path.exists(STRATUM_BINARY):
            raise Exception("%s executable not found" % STRATUM_BINARY)

    def get_stratum_cmd(self, port_map):
        args = [
            STRATUM_BINARY,
            '--device_id=%s' % str(self.device_id),
            '--forwarding_pipeline_configs_file=%s/config.txt' % STRATUM_CONFIG_DIR,
            '--persistent_config_dir=' + STRATUM_CONFIG_DIR,
            '--initial_pipeline=' + INITIAL_PIPELINE,
            '--cpu_port=%s' % self.cpu_port,
            '--external-hercules-urls=0.0.0.0:%s' % self.grpc_port,
        ]
        for port, intf in port_map.items():
            args.append('%d@%s' % (port, intf))

        cmdString = " ".join(args)
        return cmdString

    def get_cmd(self, port_map):
        bmv2_args = ['--device-id %s' % str(self.device_id)]
        for p4_port, intf_name in port_map.items():
            bmv2_args.append('-i %d@%s' % (p4_port, intf_name))
        if self.debugger:
            dbgaddr = 'ipc://%s-debug.ipc' % BMV2_RUNTIME_FILE_PATH_PREFIX
            bmv2_args.append('--debugger-addr %s' % dbgaddr)
        bmv2_args.append('--log-console')
        bmv2_args.append('-L%s' % self.loglevel)
        bmv2_args.append('--no-p4')

        # gRPC target-specific options
        bmv2_args.append('--')
        bmv2_args.append('--cpu-port %s' % self.cpu_port)
        bmv2_args.append('--grpc-server-addr 0.0.0.0:%s' % str(self.grpc_port))

        cmdString = " ".join([BMV2_TARGET_EXE] + bmv2_args)
        return cmdString

    def start(self):
        port_map = {}
        with open(self.port_map_path, 'r') as port_map_f:
            port_list = json.load(port_map_f)
            for entry in port_list:
                p4_port = entry["p4_port"]
                iface_name = entry["iface_name"]
                port_map[p4_port] = iface_name

        if self.is_stratum is True:
            cmdString = self.get_stratum_cmd(port_map)
            ld_path = STRATUM_LD_PATH + " "
        else:
            cmdString = self.get_cmd(port_map)
            ld_path = ""

        logger.info("\nStarting BMv2... %s\n" % cmdString)

        # Start the switch
        try:
            self.logfd = open(self.logfile, "w")
            self.bmv2popen = subprocess.Popen(ld_path + "exec " + cmdString,
                                              stdout=self.logfd,
                                              stderr=self.logfd,
                                              shell=True)
            self.wait_bmv2_start()
            # We want to be notified if process crashes...
            threading.Thread(target=watchdog, args=[self]).start()
        except:
            self.kill()
            raise

    def wait_bmv2_start(self):
        # Wait for switch to open gRPC port, before sending ONOS the netcfg.
        # Include time-out just in case something hangs.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        endtime = time.time() + SWITCH_START_TIMEOUT
        while True:
            result = sock.connect_ex(('127.0.0.1', self.grpc_port))
            if result == 0:  # Port is open. All good.
                sock.close()
                break
            if endtime > time.time():  # Wait...
                time.sleep(0.2)
            else:  # Time's up.
                raise Exception("Switch did not start before timeout")

    def kill(self):
        logger.info("Killing...")
        if self.bmv2popen is not None:
            self.bmv2popen.kill()
            self.bmv2popen = None
        if self.logfd is not None:
            self.logfd.close()
            self.logfd = None
