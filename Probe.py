from __future__ import print_function
from scapy.all import Dot11, RadioTap, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq  # escape ide warning
from scapy.all import *
from BaseFrame import BaseFrame
import signal
import logging
import pprint
import networkx
from multiprocessing import Process
logging.getLogger("scapy.runtime").setLevel(logging.INFO)


class Probe(BaseFrame):
    def __init__(self, interface):
        super(Probe, self).__init__(interface)
        conf.iface = self.interface
        self.networks = dict()

    def add_station_to_ap(self, sta, ap):
        print('\rDevices: [%s] ===> AP[%s]' % (sta, ap), end='')
        if ap not in self.networks:
            self.networks[ap] = list()
        if sta not in self.networks[ap]:
            self.networks[ap].append(sta)

    def sniff_callback(self, pkt):
        ap, sta = None, None

        if pkt.haslayer(Dot11ProbeReq):
            sta = pkt.getlayer(Dot11).addr2
            ap = pkt.getlayer(Dot11ProbeReq).info.decode("utf-8") or pkt.getlayer(Dot11).addr1
        if pkt.haslayer(Dot11ProbeResp):
            sta = pkt.getlayer(Dot11).addr1
            ap = pkt.getlayer(Dot11ProbeResp).info.decode("utf-8") or pkt.getlayer(Dot11).addr2
        if ap:
            self.add_station_to_ap(sta, ap)

    def sniff(self):
        self._stop_sniff = False
        print('Press CTRL+c to stop sniffing..')
        self._hopper = Process(target=self.channel_hopper)
        self._hopper.start()
        signal.signal(signal.SIGINT, self.stop_channel_hop)
        sniff(
            prn=self.sniff_callback,
            stop_filter=self.keep_sniffing)
        signal.signal(signal.SIGINT, signal.SIG_DFL)


if __name__ == '__main__':
    p = Probe('wlan0mon')
    p.sniff()
    pprint.pprint(p.networks)