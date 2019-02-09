import random
import prettytable


def dbm2quality(dbm):
    dbm = int(dbm)
    if dbm <= -100:
        quality = 0
    elif dbm >= -50:
        quality = 100
    else:
        quality = 2 * (dbm + 100)
    return quality


def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )


def print_one_ap_info(ap_info):
    channel, essid, bssid, quality = ap_info['channel'], ap_info['essid'], ap_info['bssid'], str(ap_info['quality'])
    print("\r{0:5}\t{1:20}\t{2:20}\t{3:5}".format(
        channel, essid, bssid, str(quality) + '%'
    ), end='')


def show_all_networks(networks):
    tb = prettytable.PrettyTable()
    tb.field_names = ['ID.', 'CH.', 'ESSID', 'BSSID', 'Quality']
    for idx, ap_info in enumerate(networks):
        channel, essid, bssid, quality = ap_info['channel'], ap_info['essid'], ap_info['bssid'], str(ap_info['quality'])
        tb.add_row([idx, channel, essid, bssid, str(quality)+'%'])
    print(tb)


def sort_networks(networks):
    return sorted(networks, key=lambda k: k['quality'], reverse=True)
