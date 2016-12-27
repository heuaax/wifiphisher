#!/usr/bin/env python
import sys
import os
from setuptools import setup, find_packages
from distutils.spawn import find_executable
from wifiphisher.constants import *
setup(
name = "wifiphisher",
author = "sophron|jeeinn",
author_email = "sophron@latthi.com",
description = ("利用模拟Wi-Fi热点钓鱼"),
license = "GPL",
keywords = ['wifiphisher', '中文版', '汉化版', 'phishing'],
packages = find_packages(),
include_package_data = True,
version = "1.2",
entry_points = {
'console_scripts': [
'wifiphisher = wifiphisher.pywifiphisher:run'
]
},
install_requires = [
'PyRIC',
'jinja2']
)

def get_dnsmasq():
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        install = raw_input(
            ('[' + T + '*' + W + '] dnsmasq 未找到 ' +
             '在 /usr/bin/dnsmasq, 现在安装? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S dnsmasq')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install dnsmasq')
            else:
                os.system('apt-get -y install dnsmasq')
        else:
            sys.exit(('[' + R + '-' + W + '] dnsmasq' +
                     ' 在 /usr/sbin/dnsmasq 未找到'))
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        sys.exit((
            '\n[' + R + '-' + W + '] 不能安装 \'dnsmasq\' 包!\n' +
            '[' + T + '*' + W + '] 当前网络未连接!\n' +
            '请根据链接配置你的 sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] 运行 apt-get update 来更新.\n' +
            '[' + G + '+' + W + '] 重新运行脚本来安装 dnsmasq.\n' +
            '[' + R + '!' + W + '] 关闭中...'
         ))

def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input(
            ('[' + T + '*' + W + ']' +
             '在 /usr/sbin/hostapd未找到hostapd, 现在安装? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S hostapd')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install hostapd')
            else:
                os.system('apt-get -y install hostapd')
        else:
            sys.exit(('[' + R + '-' + W + '] hostapd' +
                     ' 在 /usr/sbin/hostapd 未找到'))
    if not os.path.isfile('/usr/sbin/hostapd'):
        sys.exit((
            '\n[' + R + '-' + W + '] 不能安装 \'hostapd\' 包!\n' +
            '[' + T + '*' + W + '] 当前网络未连接!\n' +
            '请根据链接配置你的 sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] 运行 apt-get update 来更新.\n' +
            '[' + G + '+' + W + '] 重新运行脚本来安装 hostapd.\n' +
            '[' + R + '!' + W + '] 关闭中...'
         ))

def get_ifconfig():
    # This is only useful for Arch Linux which does not contain ifconfig by default
    if not find_executable('ifconfig'):
        install = raw_input(
            ('[' + T + '*' + W + '] ifconfig 命令未找到. ' +
             '现在安装? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S net-tools')
            else:
                sys.exit((
                    '\n[' + R + '-' + W + '] 安装 ifconfig 失败.\n' +
                    '[' + G + '+' + W + '] 重新运行脚本.\n' +
                    '[' + R + '!' + W + '] 关闭中...'
                ))
        else:
            sys.exit(('[' + R + '-' + W + '] ifconfig' +
                     ' 未找到'))
    if not find_executable('ifconfig'):
        sys.exit((
            '\n[' + R + '-' + W + '] 不能安装 \'net-tools\' 包!\n' +
            '[' + T + '*' + W + '] 当前网络未连接!\n' +
            '[' + G + '+' + W + '] 运行 pacman -Syu 确认更新.\n' +
            '[' + G + '+' + W + '] 重新运行脚本来安装net-tools.\n' +
            '[' + R + '!' + W + '] 关闭中...'
         ))

# Get hostapd, dnsmasq or ifconfig if needed
get_hostapd()
get_dnsmasq()
get_ifconfig()

print
print "                     _  __ _       _     _     _               "
print "                    (_)/ _(_)     | |   (_)   | |              "
print "  ((.))    __      ___| |_ _ _ __ | |__  _ ___| |__   ___ _ __ "
print "    |      \ \ /\ / / |  _| | '_ \| '_ \| / __| '_ \ / _ \ '__|"
print "   /_\      \ V  V /| | | | | |_) | | | | \__ \ | | |  __/ |   "
print "  /___\      \_/\_/ |_|_| |_| .__/|_| |_|_|___/_| |_|\___|_|   "
print " /     \                    | |                                "
print "                            |_|                                "
print "                                                               "
