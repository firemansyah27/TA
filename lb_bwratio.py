from pickle import TRUE
import random
import ryu
from ryu.lib import dpid as dpid_lib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.ofproto import ether, inet
from ryu.lib.packet import tcp
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.lib.packet import stream_parser
from ryu.ofproto import ofproto_v1_3
import requests
from operator import attrgetter
import os
from subprocess import Popen
import unicodecsv as csv
import time

class BWRatioLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(BWRatioLB, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        ########## Inisialisasi IP Address Server ##########
        self.svIp1 = "10.0.0.1"
        self.svMac1 = "00:00:00:00:00:01"
        self.svIp2 = "10.0.0.2"
        self.svMac2 = "00:00:00:00:00:02"
        self.svIp3 = "10.0.0.3"
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
        self.svIndex = 0
        self.rrStatus = True
        self.rrIndex = 0
        self.startTimer = 0
        self.portDecline = ['LOCAL', 3,4,5]
        self.bwUtil = [0,0]
        #Simpan BWRatio (dipakai untuk LB)
        self.bwMax = 12500000
        #Simpan BW Max dalam byte
        # self.bwMax = 1000
        #Digunakan setelah RR selesai
        self.serverChoose = []
        #Simpan list urutan server
        self.serverChooseIndex = 0
        self.bwmng = None
        self.csvRows = []
        self.counterServer = [0,0]
        
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
            
########## Buat paket ARP reply untuk ARP request dari client ke controller ##########
########## IP Address dan Mac Address controller di definisikan sendiri ##########
    def generate_arp_reply(self, dstMac, dstIp):
        srcMac = "12:34:56:78:9a:bc"
        srcIp = "10.0.0.100"
        pktRep = packet.Packet() #Buat paket
        ethRep = ethernet.ethernet(dstMac, srcMac, 0x0806) #Buat protokol eth
        arpRep = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp) #Buat protokol arp
        pktRep.add_protocol(ethRep) #Tambahkan ke paket
        pktRep.add_protocol(arpRep) #Tambahkan ke paket
        pktRep.serialize() #Encode Paket
        return pktRep
    
########### Fungsi proses perhitungan utilisasi bandwidth ##########
    def getBWUtil(self):
        self.csvRows.clear()
        self.serverChoose.clear()
        with open('RESULT.csv', 'rb') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=";")
            for row in csvreader:
                self.csvRows.append(row)
            for i in self.csvRows:
                if (i[1] == "s1-eth1"):
                    if (float(i[4]) != 0):
                        self.bwUtil[0] += float(i[4])
                        self.counterServer[0] += 1
                        
                if (i[1] == "s1-eth2"):
                    if (float(i[4]) != 0):
                        self.bwUtil[1] += float(i[4])
                        self.counterServer[1] += 1
                        
                # if (i[1] == "s1-eth3"):
                #     if (float(i[4]) != 0):
                #         self.bwUtil[2] += float(i[4])
                #         self.counterServer[2] += 1
                # if (i[1] == "s1-eth4"):
                #     if (float(i[4]) != 0):
                #         self.bwUtil[3] += float(i[4])
                #         self.counterServer[3] += 1
                # if (i[1] == "s1-eth5"):
                #     if (float(i[4]) != 0):
                #         self.bwUtil[4] += float(i[4])
                #         self.counterServer[4] += 1
                # if (i[1] == "s1-eth6"):
                #     if (float(i[4]) != 0):
                #         self.bwUtil[5] += float(i[4])
                #         self.counterServer[5] += 1
                # if (i[1] == "s1-eth7"):
                #     if (float(i[4]) != 0):
                #         self.bwUtil[6] += float(i[4])
                #         self.counterServer[6] += 1
            print("\n=====\nCounter server = "+str(self.counterServer)+"\n=====\n")
            for i in range(len(self.bwUtil)):
                self.bwUtil[i] = (self.bwUtil[i]/self.counterServer[i])/self.bwMax
                print("\n=====\nBW Util = "+str(self.bwUtil)+"\n=====\n")
                bwUtil_tmp = self.bwUtil.copy()
                bwUtil_sorted = sorted(bwUtil_tmp)
            for x in bwUtil_sorted:
                self.serverChoose.insert(0,bwUtil_tmp.index(x)+1)
                bwUtil_tmp[bwUtil_tmp.index(x)] = -1
                self.serverChoose.reverse()
                print("\n=====\nServer choose = "+str(self.serverChoose)+"\n=====\n")
                self.svIndex = self.serverChoose[self.serverChooseIndex]
                self.rrStatus = False
                self.startTimer = time.time()
                
    ########## Fungsi yang dijalankan ketika controller menerima packet-in ##########
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("\n packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data) #Ambil informasi paket yang masuk
        eth = pkt.get_protocols(ethernet.ethernet)[0] #Ambil ethernet frame
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dstMac = eth.dst
        srcMac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("\n Packet-In - DPID: %s SRC_MAC: %s DST_MAC: %s IN_PORT: %s", dpid, srcMac, dstMac, in_port)
        
        ########## Handle ARP Reply untuk setiap ARP request ke controller ##########
        if(eth.ethertype == 0x0806):
            self.logger.info("\n Checking ARP packet")
            arpInfo = pkt.get_protocols(arp.arp)[0] #Ambil informasi ARP
            if((arpInfo.dst_ip == "10.0.0.100") and (arpInfo.opcode == 1)):
                self.logger.info("\n ARP Packet Checking is done")
                pktRep = self.generate_arp_reply(arpInfo.src_mac, arpInfo.src_ip)
                actionsSv = [parser.OFPActionOutput(in_port)]
                arpSv = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                data=pktRep.data, actions=actionsSv, buffer_id=0xffffffff)
                self.logger.info("\n Packet-Out - DPID: %s SRC_MAC: 12:34:56:78:9a:bc DST_MAC: %s OUT_PORT: %s", dpid, srcMac, in_port) 
                datapath.send_msg(arpSv)
            return
    
        ########## Mulai koneksi TCP ke server hasil LB ##########
        self.logger.info("\n Checking TCP connection")
        if(eth.ethertype==0x0800):
            ipInfo = pkt.get_protocols(ipv4.ipv4)[0] #Ambil informasi IPv4
            if((ipInfo.dst == "10.0.0.100") and (ipInfo.proto == 0x06)):
                ########## BWUtil ##########
                ###Start BWUtil
                #Run Round robin
                if(self.rrIndex == 0):
                    print("\n\nBWMNG RUNNING\n\n")
                    self.bwmng = Popen(["bwm-ng", "-o", "csv" ,"-c", "0", "-F", "RESULT.csv"])
                    self.svIndex = 0
        
                if(self.rrStatus):
                    self.rrIndex += 1
                    print("\n\nRRINDEX "+str(self.rrIndex)+"\n\n")
                    self.svIndex += 1
                    if (self.svIndex == 3):
                        self.svIndex = 1
                    if (self.rrIndex == 15):
                        self.getBWUtil()
                    
                else:
                    if(time.time()-self.startTimer > 0.5):
                        temp = self.serverChoose[0]
                        self.serverChoose = self.serverChoose[1:]
                        self.serverChoose.append(temp)
                        self.startTimer = time.time()
                        print(self.serverChoose)
                    else:
                        self.svIndex = self.serverChoose[0]
                        
            tcpInfo = pkt.get_protocols(tcp.tcp)[0] #Ambil informasi TCP
            #Buat matching properties untuk pencocok aksi TCP di switch tingkat 1
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
            actions1=[
                parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                parser.OFPActionSetField(eth_dst="00:00:00:00:00:0"+str(self.svIndex)),
                parser.OFPActionSetField(ipv4_dst="10.0.0."+str(self.svIndex)),
                parser.OFPActionOutput(self.svIndex)
            ]
            ipInst1=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions1)]
            cookie1=random.randint(0, 0xffffffffffffffff)
            #Buat flow
            flow1=parser.OFPFlowMod(
                datapath=datapath,
                match=match1,
                idle_timeout=7,
                instructions=ipInst1,
                buffer_id=msg.buffer_id,
                cookie=cookie1
            )
            self.logger.info("\n Tambah flow host-server------->")
            self.logger.info("\n Request ke server "+str(self.svIndex)+" - IP: "+"10.0.0."+str(self.svIndex)+"Mac: "+"00:00:00:00:00:0"+str(self.svIndex))
            self.logger.info("\n Client-LB - SRC_IP: "+str(ipInfo.src)+" DST_IP: "+str(ipInfo.dst))
            self.logger.info("\n LB-Server - SRC_IP: 10.0.0.100 DST_IP: "+"10.0.0."+str(self.svIndex))
            datapath.send_msg(flow1)
            #TCP Reply
            match2 = parser.OFPMatch(
                self.svIndex,
                eth_type=eth.ethertype,
                eth_src="00:00:00:00:00:0"+str(self.svIndex),
                eth_dst="12:34:56:78:9a:bc",
                ip_proto=ipInfo.proto,
                ipv4_src="10.0.0."+str(self.svIndex),
                ipv4_dst="10.0.0.100",
                tcp_src=tcpInfo.dst_port,
                tcp_dst=tcpInfo.src_port
            )
            actions2=[
                parser.OFPActionSetField(eth_src="12:34:56:78:9a:bc"),
                parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                parser.OFPActionSetField(eth_dst=eth.src),
                parser.OFPActionSetField(ipv4_dst=ipInfo.src),
                parser.OFPActionOutput(in_port)
            ]
            ipInst2=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions2)]
            cookie2=random.randint(0, 0xffffffffffffffff)
            #Buat flow
            flow2=parser.OFPFlowMod(
                datapath=datapath,
                match=match2,
                idle_timeout=7,
                instructions=ipInst2,
                buffer_id=msg.buffer_id,
                cookie=cookie2
            )
            self.logger.info("\n Server-LB - SRC_IP: "+"10.0.0."+str(self.svIndex)+" DST_IP: 10.0.0.100")
            self.logger.info("\n LB-Client - SRC_IP: 10.0.0.100 DST_IP: "+str(ipInfo.src))
            self.logger.info("\n Tambah flow server-host------->")
            datapath.send_msg(flow2)