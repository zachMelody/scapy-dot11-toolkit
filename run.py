from scapy_toolkit import *


if __name__ == "__main__":
    interface = "wlan0"
    m = Melody(interface=interface)
    m.set_monitor_mode()
    m.deauth()
