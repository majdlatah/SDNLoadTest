# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.


import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # dpid identifies switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Parse embedded packet to get host info
        dl_dst, dl_src, eth_type = struct.unpack_from('!6s6sH',
                                                      buffer(msg.data), 0)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][dl_src] = msg.in_port

        # If we know destination, then send it to that port, else FLOOD
        if dl_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dl_dst]

            # Create output action
            actions = [ofp_parser.OFPActionOutput(out_port)]

            # Wilcard all fields except IN_PORT and DL_DST
            wildcards = ofproto.OFPFW_ALL
            wildcards &= ~ofproto.OFPFW_IN_PORT
            wildcards &= ~ofproto.OFPFW_DL_DST

            match = ofp_parser.OFPMatch(
                wildcards, msg.in_port, 0, dl_dst,
                0, 0, 0, 0, 0, 0, 0, 0, 0)

            # install a flow using flow_mod to avoid packet_in next time
            mod = ofp_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions,
                buffer_id=msg.buffer_id)

            datapath.send_msg(mod)
        else:
            # Same as what hub does
            actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

            out = ofp_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=msg.in_port, actions=actions)

            datapath.send_msg(out)
