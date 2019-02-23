from multiprocessing import Process
from scapy.all import Dot11, RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp  # escape ide warning
from scapy.all import *
from BaseFrame import BaseFrame
import signal
import utils


class Beacon(BaseFrame):
    def __init__(self, interface):
        super(Beacon, self).__init__(interface)

    def sniff(self):
        self._stop_sniff = False
        print('Press CTRL+c to stop sniffing..')
        self._hopper = Process(target=self.channel_hopper)
        self._hopper.start()
        signal.signal(signal.SIGINT, self.stop_channel_hop)
        sniff(
            lfilter=lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)),
            stop_filter=self.keep_sniffing,
            prn=lambda x: self.add_network(x))
        self.networks = utils.sort_networks(self.networks)
        print('sorted')
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    def add_network(self, pckt):
        # pckt.show()
        # Check to see if it's a hidden SSID
        raw_essid = pckt[Dot11Elt].info.decode("utf-8")
        essid = raw_essid.strip() if '\x00' not in raw_essid and raw_essid != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        # This insight was included in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)

        channel = int(ord(pckt[Dot11Elt:3].info))
        quality = utils.dbm2quality(pckt[RadioTap].dBm_AntSignal)

        if bssid not in self._known_bssids:
            ap_info = {
                'channel': channel,
                'essid': essid,
                'bssid': bssid,
                'quality': quality,
            }
            self._known_bssids.append(bssid)
            self.networks.append(ap_info)
            utils.print_one_ap_info(ap_info)

    def send(self, ssid='Input your SSID'):
        random_mac_addr = utils.rand_mac()

        dot11 = Dot11(type=0, subtype=8,  # type : management frame, subtype: beacon frame
                      addr1='ff:ff:ff:ff:ff:ff',
                      addr2=random_mac_addr, addr3=random_mac_addr)
        beacon = Dot11Beacon()
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        rsn = Dot11Elt(ID='RSNinfo', info=(
            '\x01\x00'
            '\x00\x0f\xac\x02'
            '\x02\x00'
            '\x00\x0f\xac\x04'
            '\x00\x0f\xac\x02'
            '\x01\x00'
            '\x00\x0f\xac\x02'
            '\x00\x00'))
        frame = RadioTap() / dot11 / beacon / essid / rsn
        sendp(frame, iface=self.interface, inter=0.100, loop=1)


if __name__ == '__main__':
    beacon = Beacon(interface='wlan0mon')
    # beacon.send(ssid='Test SEBD')
    beacon.sniff()
    utils.show_all_networks(beacon.networks)