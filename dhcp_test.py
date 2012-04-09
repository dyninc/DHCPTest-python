#!/usr/bin/env python

'''
Script will load test a DHCP server by continuosly requesting address leases in a loop using randomly generated mac addresses. This will run serially as written, if you want to have multiple scripts running you will
need to run it in several processes. Be aware that if you run it in multiple processes you may run into a number of lease failures on your DHCP client
do to multiple discover packets hitting before a request hits thus several requests for the same address may occur. This is the normal behavior as in a real
setup a client would then retry several times in the event this occurs. (one thing you *MAY* need to do is set promiscuous for the pcap object -> the open_live call)

This is by no means a comprehensive DHCP test, just a little one off script to vefiy that a server is able to handle load numbers.

-Couple of pretty simple but sometimes forgotten notes:
  *Make sure your DHCP server is reachable via it's IP (the client curring the script can see the subnet it's on) 
  *Make sure your DHCP server isn't attempting to lease its own ip (in other words don't assign an ip for testing within the lease range)

Usage: dhcp_test.py [DHCP server IP] [DHCP server port - Optional defaults to 67] [Number of Loops - Optional defaults to 1]

'''

from random import Random
from optparse import OptionParser
from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.dhcp_network import DhcpClient
from pydhcplib.type_hw_addr import hwmac
from pydhcplib.type_ipv4 import ipv4
import socket
import sys
import time
import pcap
import struct

r = Random()
r.seed()

break_wait = 0
res = None

dhcp_ip = ''

# generamte a random mac address
def genmac():
        i = []
        for z in xrange(6):
                i.append(r.randint(0,255))
        return ':'.join(map(lambda x: "%02x"%x,i))

#generate a random xid
def genxid():
        decxid = r.randint(0,0xffffffff)
        xid = []
        for i in xrange(4):
                xid.insert(0, decxid & 0xff)
                decxid = decxid >> 8
        return xid

def get_packet(pktlen, data, timestamp):
        global dhcp_ip
	global break_wait
        global res
        if not data:
                return
        if data[12:14]=='\x08\x00':
                decoded=decode_ip_packet(data[14:])
                if decoded['source_address'] == dhcp_ip:
                        res = decoded['destination_address'] # take advantage of CNR using the new ip as the desination address...
                        break_wait = 1

# send the request to the server
def issueRequest(serverip, serverport, timeout, req):
        global break_wait
        global res

        # Reset the global vars we will use here
        break_wait = 0
        res = None
        client = DhcpClient(client_listen_port=67, server_listen_port=serverport)
        client.dhcp_socket.settimeout(timeout)
        if serverip == '0.0.0.0':
                req.SetOption('flags',[128, 0])
        req_type = req.GetOption('dhcp_message_type')[0]

        pcap_obj = pcap.pcapObject()
        dev = pcap.lookupdev()
        pcap_obj.open_live(dev, 1600, 0, 100)
        pcap_obj.setfilter("udp port 67", 0, 0)
        sent = 0
        while break_wait < 1:
                if(sent < 1):
                        sent = 1
                        client.SendDhcpPacketTo(req,serverip,serverport)
                if req_type == 3 or req_type == 7:
                        return
                pcap_obj.dispatch(1, get_packet)

        return res

#set up a dhcp packet, this defaults to the discover type
def preparePacket(xid=None,giaddr='0.0.0.0',chaddr='00:00:00:00:00:00',ciaddr='0.0.0.0', yiaddr='0.0.0.0', msgtype='discover',required_opts=[]):
        req = DhcpPacket()
        req.SetOption('op',[1])
        req.SetOption('htype',[1])
        req.SetOption('hlen',[6])
        req.SetOption('hops',[0])
        if not xid:
                xid = genxid()
        req.SetOption('xid',xid)
        req.SetOption('giaddr',ipv4(giaddr).list())
        req.SetOption('chaddr',hwmac(chaddr).list() + [0] * 10)
        req.SetOption('ciaddr',ipv4(ciaddr).list())
        if msgtype == 'request':
                mt = 3
        elif msgtype == 'release':
                mt = 7
        else:
                mt = 1
        if mt == 3:
                req.SetOption('yiaddr', ipv4(yiaddr).list())
                req.SetOption('request_ip_address', ipv4(yiaddr).list())
        req.SetOption('dhcp_message_type',[mt])
        return req

# decode the packect so we can get information such as the source address to verify if the reply is comeing from where we expect
def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

# start of the global section, this is the "main" entry point
dhcp_ip = "0.0.0.0"
dhcp_port = 67
loops = 1
if len(sys.argv) != 3 and len(sys.argv) != 4 and  len(sys.argv) != 5:
	pass
	print "Usage: dhcp_test.py [DHCP server IP] [DHCP server port - Optional defaults to 67] [Number of Loops - Optional defaults to 1]"
	sys.exit(0)
elif len(sys.argv) != 4 and  len(sys.argv) != 5:
	loops = 1
	dhcp_port = 67
	dhcp_ip = sys.argv[1]
elif len(sys.argv) != 5:
	loops = 1
	dhcp_ip = sys.argv[1]
	dhcp_port = int(sys.argv[2])
else:
	loops =  int(sys.argv[3])
	dhcp_port = int(sys.argv[2])
	dhcp_ip = sys.argv[1]
	
leases = {}
run_loops = loops
#run this as many times as needed to test your server
while run_loops > 0:
	#get a mac address
	mac = genmac()
	
	# create a discovery packet
	disc_packet = preparePacket(None, '0.0.0.0', mac, '0.0.0.0', '0.0.0.0', 'discover', [1,3,6,51])
	
	#send the discover request to the server
	ip_issued = issueRequest(dhcp_ip, dhcp_port, 4, disc_packet)
	
	# use the returned discovered ip to create a request packet
	req_packet = preparePacket(None, '0.0.0.0', mac, '0.0.0.0', ip_issued, 'request', [1,3,6,51])
	
	#issue the actual lease request
	res = issueRequest(dhcp_ip, dhcp_port, 4, req_packet)
	
	#just print out if we get a bad lease reply
	if ip_issued == '255.255.255.255':
		print mac
		print ip_issued
		print "error getting lease"
	else:
		leases[ip_issued] = mac
	run_loops = run_loops - 1

#pause before we release all of the addresses in case we want to view them in the DHCP server
entered  = raw_input("Press 'Enter' key to continue...")

#loop through all our leases and tell the DHCP server we are done with them 
for k, v in leases.iteritems():
	rel_packet = preparePacket(None, '0.0.0.0', v, k, '0.0.0.0', 'release', [1,3,6,51])
	ip_issued = issueRequest(dhcp_ip, dhcp_port, 4, rel_packet)
