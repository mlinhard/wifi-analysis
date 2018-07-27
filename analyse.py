#!/usr/bin/python3
"""Analyse captured packets from Wi-Fi interface 

Usage:
  analyse.py <pcap-file> <config-file>

Options:
  -h --help   Show this screen
  --version   Show version
"""
from docopt import docopt
from scapy.layers.dot11 import Dot11
from scapy.utils import rdpcap
import json
from builtins import set


class Config(object):
    
    def __init__(self, file):
        with open(file , "r") as f:
            config_json = json.load(f)
        base_stations = config_json.get("base_stations")
        if not base_stations:
            raise "No base stations defined"
        self._bssid_set = set(base_stations)
        self._known_addrs = config_json.get("known_addresses")
        if not self._known_addrs:
            self._known_addrs = {}

    def get_name(self, addr):
        name = self._known_addrs.get(addr)
        return name if name else addr

    def is_base(self, packet):
        if packet.addr1 in self._bssid_set:
            return True
        if packet.addr2 and packet.addr2 in self._bssid_set:
            return True
        if packet.addr3 and packet.addr3 in self._bssid_set:
            return True
        return False


if __name__ == '__main__':
    args = docopt(__doc__, version="0.1.0")
    config = Config(args['<config-file>'])
    print("Loading file {}".format(args['<pcap-file>']))
    packets = rdpcap(args['<pcap-file>'])
    print("Loaded {} packets".format(len(packets)))

    non11_count = 0
    tuples = {}
    for packet in packets:
        if packet.haslayer(Dot11):
            if config.is_base(packet):
                t = (packet.addr1, packet.addr2, packet.addr3, packet.type, packet.subtype)
                tuple_count = tuples.get(t)
                tuples[t] = (tuple_count if tuple_count else 0) + 1
        else:
            non11_count += 1

    for bssid in config._bssid_set:
        print(config.get_name(bssid) + "\n")
        
        for t, c in tuples.items():
            if bssid == t[0]:
                print("> {} typ {} sub {} cnt {}".format(t[1], t[3], t[4], c))
            elif bssid == t[1]:
                print("< {} typ {} sub {} cnt {}".format(t[0], t[3], t[4], c))
            elif bssid == t[2]:
                print("{} > {} typ {} sub {} cnt {}".format(t[1], t[0], t[3], t[4], c))
            else:
                print("ERROR typ {} sub {} cnt {}".format(t[3], t[4], c))
        
