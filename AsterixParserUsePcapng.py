import dpkt
import socket
from datetime import datetime
from dpkt.compat import compat_ord
import asterix4py
import json
import argparse
import os

def createDirectory(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
    except OSError:
        print ('Error whlie making a directory for' +  path)

def dumpJsonFile(id, asterix):
    createDirectory('parsed')
    filename = ".\\parsed\\asterix" + str(id) + ".json"
    f = open(filename, 'w')
    f.write(asterix)
    f.close()

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def decodeAsterix(payload, isDump=False, cnt=0):
        print('.', end='')

        # start_time = datetime.now()
        decoder = asterix4py.AsterixParser(payload)
        # end_time = datetime.now()
        # print("걸린 시간:", end_time-start_time)

        dump = decoder.get_result()
        asterix = json.dumps(dump, sort_keys=True, indent=4)
        if(isDump):
            dumpJsonFile(id=cnt, asterix=asterix)

def parsePcapng(pcapng):
    id = 0
    start_time = datetime.now()

    for timestamp,buf in pcapng:
        id = id + 1
        eth=dpkt.ethernet.Ethernet(buf)
        # print('timestamp: ', str(datetime.utcfromtimestamp(timestamp)))
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        ip=eth.data
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

        payload = ip.data.data[100:-1]
        decodeAsterix(payload=payload, isDump=True, cnt=id)
        # printPackets(ip.data.data)

    end_time = datetime.now()
    print("\n전체 걸린 시간:", end_time-start_time, id,"건처리")

def printPackets(data):
    if(len(data) > 104):
        pktType1 = [int(i) for i in data[0:1]][0]
        pktType2 = [int(i) for i in data[67:68]][0]
        pktType3 = [int(i) for i in data[93:94]][0]

        length = [(str(i)) for i in data[3:7]]
        
        print("###############################################")
        print("Advanced Message Queuing Protocol")
        print("###############################################")
        print("Type:", pktType1)
        print("Channel:", [(str(i)) for i in data[1:3]])
        print("Length:", length)
        print("Length:", [(str(i)) for i in data[3:7]])
        print("Class:", [(str(i)) for i in data[7:9]])
        print("Method:", [(str(i)) for i in data[9:11]])
        print("-----------------------------------------------")
        print("\tConsumer-Tag:", data[12:43])
        print("\tExchange", data[53:65])
        print("-----------------------------------------------")
        print("Type:", pktType2)
        print("Channel:", [(str(i)) for i in data[68:70]])
        print("Length:", [(str(i)) for i in data[70:74]])
        print("Class ID:", [(str(i)) for i in data[74:76]])
        print("Weight:", [(str(i)) for i in data[76:78]])
        print("Body size:", [(str(i)) for i in data[78:86]])
        print("Property flags:", [(str(i)) for i in data[86:88]])
        print("Properties:", [(str(i)) for i in data[88:92]])
        print("-----------------------------------------------")
        print("Type:", pktType3)
        print("Channel:", [(str(i)) for i in data[94:96]])
        print("Length:", [(str(i)) for i in data[96:100]])
        print("Payload:", data[100:-1])
        print("###############################################")

def test(filename):
    """Open up a test pcap file and print out the packets"""
    with open(filename, 'rb') as f:
        packet = dpkt.pcapng.Reader(f)
        pcapng = packet.readpkts()
        parsePcapng(pcapng)
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', help="input pcapng filename", required=True)
    args = parser.parse_args()
    print( {args.filename} )
    filename = args.filename
    test(filename)
