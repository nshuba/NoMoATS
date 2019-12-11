# This file is part of AutoLabel <http://athinagroup.eng.uci.edu/projects/autolabel/>.
# Copyright (C) 2019 Anastasia Shuba, University of California, Irvine.
#
# AutoLabel is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 2 of the License only.
#
# AutoLabel is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with AutoLabel.  If not, see <http://www.gnu.org/licenses/>.

import frida
import os
import sys
import binascii
import logging
import json
import time
import uuid
import pcapng.block
import pcapng.linktype
import pcapng.option

from socket import AF_INET
from threading import Lock

import frida_net_layers

class FridaController(object):
    """
    this class controls and communicates with Frida
    """

    # Interface ID needed by the EPB object
    INTERFACE_ID = 0
    TRACE_KEY = 'trace'
    IP_LEVEL_KEY = 'ip_level'
    URL_KEY = 'url'
    HEADERS_KEY = 'headers'
    BASE_HEX = 16
    
    # JS msg types
    TYPE_STOP = "stop";
    TYPE_INFO = "info";
    TYPE_LIB  = "lib";
    TYPE_DATA = "data";
    TYPE_WEB_LOAD = "web_load";
    TYPE_WEB_INTC = "web_intc";

    def __init__(self, output_dir, package_name):      
        self.enabled = True
        self.logger = logging.getLogger(self.__class__.__name__)
        self.package_name = package_name
        
        # Prepare for saving native library loading
        self.output_dir = output_dir
        self.native_libs = []
        
        # Prepare for keeping track of web views
        self.webview_intc = {}
        
        # Prepare pcap file - from: https://github.com/cloojure/pcapng
        # PCAPNG files must begin with a Section Header Block:
        self.pcap_fp = open(os.path.join(output_dir, package_name + '.pcapng'), 'wb')

        shb_opts = [ pcapng.option.ShbHardware("Nexus 6"),
                     pcapng.option.ShbOs("Android"),
                     pcapng.option.ShbUserAppl("Frida") ]
        shb_obj = pcapng.block.SectionHeaderBlock(shb_opts)
        shb_packed_bytes = shb_obj.pack()
        self.pcap_fp.write(shb_packed_bytes)  # must be 1st block

        # After the SHB, one or more Interface Description Blocks may be included:
        idb_opts = [ pcapng.option.IdbName("fake_eth"),
                     pcapng.option.IdbDescription("frida capture"),
                     pcapng.option.IdbSpeed(92160) ] # About 90Mbps in our lab - doesn't really matter
        idb_obj = pcapng.block.InterfaceDescBlock(pcapng.linktype.LINKTYPE_RAW, idb_opts)
        self.pcap_fp.write(idb_obj.pack())
        
        # Prepare basic tcp header
        self.tcp_header = frida_net_layers.create_tcp_header()
        self.frida_device = frida.get_usb_device()
        self.frida_device.on('process-crashed', self.on_process_crashed)
        
        self.start_app_lock = Lock()
        self.app_pid = -1
        
    def start_app(self):
        """
        Checks to see if the app we started earlier is still running. If not, re-start
        """            
        if not self.start_app_lock.acquire(False):
            # If we can't acquire the lock - another thread is already starting the app
            self.logger.info("start_app_lock not acquired - returning...")
            return
            
        try:
            curr_pid = self.frida_device.get_process(self.package_name).pid
            if self.app_pid != curr_pid:
                self.logger.info("App pid mismatch: %d vs %d. Re-starting using Frida...", self.app_pid, curr_pid)
                self._start_app()
        except frida.ProcessNotFoundError:
            self.logger.info("App not running. Using Frida to start it...")
            self._start_app()
        finally:
            self.start_app_lock.release()
        
    def _start_app(self):
        """
        Spawns the app and injects Frida before the app finishes launch
        """            
        self.app_pid = self.frida_device.spawn([self.package_name])
        # Save pid. Then if in start_app check Device.get_process to match pid
        session = self.frida_device.attach(self.app_pid)
        self.load_script(session)        
        self.logger.info("Script loaded, resuming app")
        self.frida_device.resume(self.app_pid)
        
    def load_script(self, session):
        """
        Injects the Frida agent JavaScript into the app session
        """
        dir_path = os.path.dirname(os.path.realpath(__file__))            
        script = os.path.join(dir_path, "frida_agent.js")
        with open(script, mode="rb") as f:
            js = f.read().decode("UTF-8")
            script = session.create_script(js)
        
        session.on('detached', self.on_detached)
        script.on('message', self.on_message)
        script.load()
        
    def on_process_crashed(self, crash):
        self.logger.info("on_process_crashed")
        self.logger.info(crash)
        
        # On detached is not always called automatically
        self.on_detached("crash", crash)

    def on_detached(self, reason, crash):
        self.logger.info("on_detached()")
        self.logger.info(reason)
        self.logger.info(crash)
        
        self.logger.info("Attempting restart...")
        self.start_app()
        
    def error_stop(self, reason):
        self.logger.error("Stopping main thread. Reason:")
        self.logger.error(reason)
        self.enabled = False
                    
    def on_message(self, message, data):
        if not self.enabled:
            return
            
        if message['type'] == 'error':
            self.logger.error(message['description'])
            print "In file " + message['fileName'] + ":" + str(message['lineNumber'])
            print message['stack']
            return
        
        msg_data = message['payload']
        msg_type = msg_data['type']
        if msg_type == FridaController.TYPE_STOP:
            self.logger.info("Stopping main thread...")
            self.logger.info("Reason: " + str(msg_data.get('reason')))
            self.enabled = False
            return
            
        if msg_type == FridaController.TYPE_LIB:
            key_lib = "lib"
            self.logger.info("Native library loaded: " + msg_data.get(key_lib))
            self.native_libs.append(msg_data)
            return
            
        if msg_type == FridaController.TYPE_INFO:
            self.logger.info("From JS: " + msg_data.get('info'))
            return
            
        if msg_type == FridaController.TYPE_WEB_INTC:            
            #print msg_data[FridaController.URL_KEY] 
            
            del msg_data['type']
            msg_data["ts"] = str(time.time())
            self.webview_intc[str(uuid.uuid4())] = msg_data
            return
            
        if FridaController.TRACE_KEY not in msg_data:
            # This usually happens for the first packet only
            self.logger.warning("No trace detected!")
            msg_data[FridaController.TRACE_KEY] = "no trace"      
            
        # Convert to bytearray
        data_bytes = bytearray(data)
        
        # First two bytes are the port number:
        port_len = 2
        port_bytes = data_bytes[:port_len]
        port = int(binascii.hexlify(port_bytes), FridaController.BASE_HEX)
        
        # IP address follows the port number
        # IPv6 - 16 bytes for the address
        addr_len = 16
        if msg_data.get(FridaController.IP_LEVEL_KEY) == AF_INET:
            # IPv4 - 4 bytes for the address
            addr_len = 4
        ip_bytes = data_bytes[port_len:port_len+addr_len]
        
        # Python handles overflow, so we just convert to int:
        ip = int(binascii.hexlify(ip_bytes), FridaController.BASE_HEX)
        
        # The rest is data:
        data_offset = port_len + addr_len
        data_len = len(data_bytes) - data_offset
        packet_data = data_bytes[data_offset:len(data_bytes)]
        
        # Test if this is an IPv4 address or an IPv4-mapped IPv6 address. 
        # IPv4-mapped IPv6 addresses "consist of an 80-bit prefix of zeros, 
        # the next 16 bits are ones, and the remaining, least-significant 32 bits contain the IPv4 address"
        # https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
        # This translates into the following mask:
        if msg_data.get(FridaController.IP_LEVEL_KEY) == AF_INET or (ip >> 32) == 0xffff:
            # This is an IPv4-mapped address, so we only need the last 32 bits (4 bytes)
            ipv4_addr_len = 4
            ipv4_bytes = ip_bytes[addr_len-ipv4_addr_len:addr_len]
            ip_header = frida_net_layers.create_ipv4_header(ipv4_bytes, data_len)
            frida_net_layers.update_dst_port(self.tcp_header, port)
            
            # Append packet block:  
            complete_packet = ip_header + self.tcp_header + packet_data
            epb_opts = [pcapng.option.Comment(msg_data[FridaController.TRACE_KEY].encode('ascii', 'replace'))]
            self.pcap_fp.write(pcapng.block.EnhancedPacketBlock(
                FridaController.INTERFACE_ID, complete_packet, len(complete_packet), epb_opts).pack())
        else:
            self.logger.error("Non-IPv4 mapped IPv6 address!")
            self.enabled = False

    def stop(self):
        self.logger.info("Frida stopping")
        self.enabled = False
        self.pcap_fp.close()
        
        if len(self.native_libs) != 0:
            json_path = os.path.join(self.output_dir, 'nativelibs.json')
            with open(json_path, "w") as jf:
                jf.write(json.dumps(self.native_libs, indent=4))
                
        if len(self.webview_intc) != 0:
            json_path = os.path.join(self.output_dir, 'webview_loads.json')
            with open(json_path, "w") as jf:
                jf.write(json.dumps(self.webview_intc, indent=4))
            