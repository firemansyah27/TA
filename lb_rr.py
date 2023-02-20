from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib.packet import tcp
from ryu.ofproto import ether, inet
from ryu.lib.packet import icmp
import time as time
from ryu.lib.packet import arp
from ryu.lib import ip as ip_lib
from ryu.lib import mac as mac_lib
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.controller import ofp_event
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib
import ryu
import random


class RoundRobinLB(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(RoundRobinLB, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        ########## Inisialisasi IP Address Server ##########
        self.svIp1 = "10.0.0.1"
        self.svMac1 = "00:00:00:00:00:01"
        self.svIp2 = "10.0.0.2"
        self.svMac2 = "00:00:00:00:00:02"
        # self.svIp3 = "10.0.0.3"
        # self.svMac3 = "00:00:00:00:00:03"
        # self.svIp4 = "10.0.0.4"
        # self.svMac4 = "00:00:00:00:00:04"
        # self.svIp5 = "10.0.0.5"
        # self.svMac5 = "00:00:00:00:00:05"
        # self.svIp6 = "10.0.0.6"
        # self.svMac6 = "00:00:00:00:00:06"
        # self.svIp7 = "10.0.0.7"
        # self.svMac7 = "00:00:00:00:00:07"
        ########## Variabel untuk menentukan server dipilih ##########
        self.svIndex = 1
        
    ########## Fungsi untuk inisiasi hubungan switch-controller ##########
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        
    # Buat paket ARP reply untuk ARP request dari client ke controller
    ##########
    ########## IP Address dan Mac Address controller di definisikan sendiri ##########
    def generate_arp_reply(self, dstMac, dstIp):
        srcMac = "12:34:56:78:9a:bc"
        srcIp = "10.0.0.100"
        pktRep = packet.Packet()  # Buat paket
        ethRep = ethernet.ethernet(dstMac, srcMac, 0x0806)  # Buat protokol eth
        arpRep = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp,
                        dstMac, dstIp)  # Buat protokol arp
        pktRep.add_protocol(ethRep)  # Tambahkan ke paket
        pktRep.add_protocol(arpRep)  # Tambahkan ke paket
        pktRep.serialize()  # Encode Paket
        return pktRep
        
    ########## Fungsi yang dijalankan ketika controller menerima packet-in ##########
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("\n packet truncated: only %s of %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)  # Ambil informasi paket yang masuk
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # Ambil ethernet frame
            
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dstMac = eth.dst
        srcMac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("\n Packet-In - DPID: % s SRC_MAC: % s DST_MAC: % s IN_PORT: % s", dpid, srcMac, dstMac, in_port)
            
    ########## Handle ARP Reply untuk setiap ARP request ke controller ##########
        if (eth.ethertype == 0x0806):
            self.logger.info("\n Checking ARP packet")
            arpInfo = pkt.get_protocols(arp.arp)[0]  # Ambil informasi ARP
            if ((arpInfo.dst_ip == "10.0.0.100") and (arpInfo.opcode == 1)):
                self.logger.info("\n ARP Packet Checking is done")
                pktRep = self.generate_arp_reply(arpInfo.src_mac, arpInfo.src_ip)
                actionsSv = [parser.OFPActionOutput(in_port)]
                arpSv = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                                            data=pktRep.data, actions=actionsSv, buffer_id=0xffffffff)
                self.logger.info("\n Packet-Out - DPID: % s SRC_MAC: 12:34:56:78:9a:bc DST_MAC: % s OUT_PORT: % s", dpid, srcMac, in_port)
                datapath.send_msg(arpSv)
            return
    ########## Mulai koneksi TCP ke server hasil LB ##########
        self.logger.info("\n Checking TCP connection")
        # Pilih server berdasarkan server index
        if (self.svIndex == 1):
            svIP = self.svIp1
            svMac = self.svMac1
        elif (self.svIndex == 2):
            svIP = self.svIp2
            svMac = self.svMac2
        # elif (self.svIndex == 3):
        #     svIP = self.svIp3
        #     svMac = self.svMac3
        # elif (self.svIndex == 4):
        #     svIP = self.svIp4
        #     svMac = self.svMac4
        # elif (self.svIndex == 5):
        #     svIP = self.svIp5
        #     svMac = self.svMac5
        # elif (self.svIndex == 6):
        #     svIP = self.svIp6
        #     svMac = self.svMac6
        # elif (self.svIndex == 7):
        #     svIP = self.svIp7
        #     svMac = self.svMac7
            
        if (eth.ethertype == 0x0800):
            ipInfo = pkt.get_protocols(ipv4.ipv4)[0]  # Ambil informasi IPv4
            if ((ipInfo.dst == "10.0.0.100") and (ipInfo.proto == 0x06)):
                time.sleep(0.11)
                tcpInfo = pkt.get_protocols(tcp.tcp)[0]  # Ambil informasi TCP
                # Buat matching properties untuk pencocok aksi TCP di switch tingkat 1
                match1 = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_src=eth.src,
                    eth_dst=eth.dst,
                    ip_proto=ipInfo.proto,
                    ipv4_src=ipInfo.src,
                    ipv4_dst=ipInfo.dst,
                    tcp_src=tcpInfo.src_port,
                    tcp_dst=tcpInfo.dst_port
                )
                actions1 = [
                    parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                    parser.OFPActionSetField(eth_dst=svMac),
                    parser.OFPActionSetField(ipv4_dst=svIP),
                    parser.OFPActionOutput(self.svIndex)
                ]
                
            ipInst1 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions1)]
            cookie1 = random.randint(0, 0xffffffffffffffff)
            # Buat flow
            flow1 = parser.OFPFlowMod(
                datapath=datapath,
                match=match1,
                idle_timeout=7,
                instructions=ipInst1,
                buffer_id=msg.buffer_id,
                cookie=cookie1
            )
            self.logger.info("\n Tambah flow host-server------->")
            self.logger.info("\n Request ke server "+str(self.svIndex)+" - IP: "+str(svIP) +"Mac: "+str(svMac))
            self.logger.info("\n Client-LB - SRC_IP: "+str(ipInfo.src) +" DST_IP:"+str(ipInfo.dst))
            self.logger.info("\n LB-Server - SRC_IP: 10.0.0.100 DST_IP: "+str(svIP))
            datapath.send_msg(flow1)
            # TCP Reply
            match2 = parser.OFPMatch(
                self.svIndex,
                eth_type=eth.ethertype,
                eth_src=svMac,
                eth_dst="12:34:56:78:9a:bc",
                ip_proto=ipInfo.proto,
                ipv4_src=svIP,
                ipv4_dst="10.0.0.100",
                tcp_src=tcpInfo.dst_port,
                tcp_dst=tcpInfo.src_port
            )
            actions2 = [
                parser.OFPActionSetField(eth_src="12:34:56:78:9a:bc"),
                parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                parser.OFPActionSetField(eth_dst=eth.src),
                parser.OFPActionSetField(ipv4_dst=ipInfo.src),
                parser.OFPActionOutput(in_port)
            ]
            ipInst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions2)]
            cookie2 = random.randint(0, 0xffffffffffffffff)
            # Buat flow
            flow2 = parser.OFPFlowMod(
                datapath=datapath,
                match=match2,
                idle_timeout=7,
                instructions=ipInst2,
                buffer_id=msg.buffer_id,
                cookie=cookie2
            )
            self.logger.info("\n Server-LB - SRC_IP: "+str(svIP)+" DST_IP: 10.0.0.100")
            self.logger.info("\n LB-Client - SRC_IP: 10.0.0.100 DST_IP: "+str(ipInfo.src))
            self.logger.info("\n Tambah flow server-host------->")
            datapath.send_msg(flow2)
            self.svIndex += 1
            if (self.svIndex == 3):
                self.svIndex = 1
