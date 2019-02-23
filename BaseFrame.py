from scapy.all import *
import os


class BaseFrame(object):
    def __init__(self, interface='wlan0mon'):
        self.interface = interface if 'mon' in interface else interface + 'mon'
        conf.iface = self.interface
        self.networks = list()          # store all sniffed ap or station
        self._known_bssids = list()     # store the sniffed of all received ap or station
        self._channels = [              # available channels
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,      # 2.4G
            # 36, 40, 44, 48,                                 # 5G UNII-1
            # 52, 56, 60, 64, 149, 153, 157, 161              # 5G UNII-2/3
        ]
        self._cur_channel = 1           # current channel
        self._stop_sniff = False        # the state of sniffing
        self._hopper = None             # the thread of sniffing

    def channel_hopper(self):
        while True:
            try:
                self._cur_channel = self._channels[random.randrange(1, len(self._channels))]
                cmd = "iwconfig %s channel %d" % (self.interface, self._cur_channel)
                os.system(cmd)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def stop_channel_hop(self, received_signal, frame):
        # set the stop_sniff variable to True to stop the sniffer
        self._stop_sniff = True
        self._hopper.terminate()
        self._hopper.join()

    def keep_sniffing(self, pckt):
        return self._stop_sniff

    def sniff(self):
        pass

    def send(self):
        pass
