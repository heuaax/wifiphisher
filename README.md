<p align="center"><img src="https://sophron.github.io/wifiphisher/wifiphisher.png" /></p>

## 说明
<a href="https://wifiphisher.org">Wifiphisher</a> 是一个无线 Wi-Fi 渗透安全工具。不使用暴力破解，利用社会工程学，进行定制的 Wi-Fi 钓鱼页面来欺骗用户，以获取数据（如 Wi-Fi 密码，社交账号，路由器密码等）.

Wifiphisher 运行在 `Kali Linux` 系统上，使用 `GPL` 许可证.

## 运行原理
发起中间攻击，图片上 `Victim` 是受骗者，`Target Ap` 是对方 `Wi-Fi`

从受骗者角度来说, 攻击分为三个部分:

1. **受骗者会从自己连接的 Wi-Fi 掉线**. 因为 Wifiphisher 使用 `Deauthenticate` 或者 `Disassociate` 数据包攻击受骗者的 Wi-Fi，迫使其 Wi-Fi 不能响应，造成假死，死机.
2. **受骗者加入模拟的Wi-Fi**. Wifiphisher 会伪造出一个和受骗用户的 Wi-Fi 一摸一样的热点. 同时设置一个 `NAT/DHCP` 服务用来转发数据. 最终导致受骗者连上伪造的 `Wi-Fi`.
3. **受骗者会访问到钓鱼页面**. Wifiphisher 建立一个网页微服务可以响应 `HTTP & HTTPS` 的请求. 当用户访问网络时 Wifiphisher 会弹出钓鱼页面，用户输入的内容会被记录.

<p align="center"><img width="70%" src="https://sophron.github.io/wifiphisher/diagram.jpg" /><br /><i>演示攻击</i></p>

## 要求
运行 Wifiphisher 的必备条件:

* `Kali Linux`.官方推荐运行系统 ，当然也可以运行在其他 `Linux` 系统(你可能要安装很多其他依赖).
* 一块支持 AP 模式的网卡. 用来伪造 Wi-Fi 驱动支持 `netlink`.
* 一块监听模式的网卡来捕获注入数据包. 如果第二块网卡不能用, 你或许使用了 `--nojamming` 命令选项. 这个命令会关闭攻击命令.

## 安装

输入一下命令安装:

```
git clone https://github.com/jeeinn/wifiphisher.git # 下载最新版本
cd wifiphisher # 切换到文件所在目录
sudo python setup.py install # 安装依赖 (例如： hostapd, PyRIC, jinja2)
```

当然你也可以下载 <a href="https://github.com/sophron/wifiphisher/releases">稳定版</a>.

## 使用

在文件所在目录下输入 `wifiphisher` 或 `python bin/wifiphisher` .

这将自动扫描附近 Wi-Fi 并根据提示来伪造一个 Wi-Fi，并启动钓鱼页面.

***

```
wifiphisher -aI wlan0 -jI wlan4 -p firmware-upgrade
```

设定使用 `wlan0` 伪造 Wi-Fi 热点 ， 设定 `wlan4` 作为攻击使用，`-p` 指定 "固件升级" 钓鱼页面:"Firmware Upgrade" .

可以非常方便的设定网卡. <a href="https://wifiphisher.org/ps/firmware-upgrade/">"Firware Upgrade"</a> 页面非常使用去骗取使用者的加密Wi-Fi密码，现已经替换为"网络修复".

***

```shell
wifiphisher --essid CONFERENCE_WIFI -p plugin_update -pK s3cr3tp4ssw0rd
```

自动识别网卡. 设定要伪造的 Wi-Fi 的名字（ESSID）如： "CONFERENCE_WIFI" 和使用"插件更新"钓鱼页面 "Plugin Update" . 添加 PSK 加密的密码 "s3cr3tp4ssw0rd" .

开放Wi-Fi，公共热点 .  <a href="https://wifiphisher.org/ps/plugin_update/">"Plugin Update"</a> 提供简单的页面诱导受骗者去下载恶意程序 .

***

```shell
wifiphisher --nojamming --essid "FREE WI-FI" -p oauth-login
```

不进行攻击. 伪造一个简易的 Wi-Fi 名字叫 "FREE WI-FI" ，同时使用 "OAuth Login" 钓鱼页面.

适合在公共场所使用.  <a href="https://wifiphisher.org/ps/oauth-login/">"OAuth Login"</a> 支持捕捉社交登陆的如QQ.

命令介绍 (使用命令 `wifiphisher -h`):

| 短命令 | 长命令 | 介绍 |
| :----------: | :---------: | :-----------: |
|-h  | --help| 显示帮助信息 |
|-s  | --skip | 跳过攻击指定的 MAC 地址. 如: -s 00:11:BB:33:44:AA|
|-jI  | --jamminginterface |	设定支持监听模式的网卡用来攻击. 如: -jI wlan1|
|-aI  | --apinterface | 设定支持AP模式的网卡用来伪造Wi-Fi. 如: -aI wlan0|
|-t  | --timeinterval | 设定攻击包发送的时间间隔|
|-dP  | --deauthpackets |设定同时发送给受骗者和真实Wi-Fi的攻击包数量. 如: -dP 2|
|-d  | --directedonly| Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs|
|-nJ  | --nojamming| 跳过攻击. 这时只需要一块网卡即可|
|-e  | --essid |	设定伪造Wi-Fi的名字. 如: --essid 'Free WiFi'|
|-p  | --phishingscenario | 选择钓鱼页面. 如: -p firmware_upgrade|
|-pK  | --presharedkey |	为伪造的Wi-Fi添加 WPA/WPA2 密码. 如: -pK s3cr3tp4ssw0rd|




## 截图

<p align="center"><img src="https://sophron.github.io/wifiphisher/ss5.png" /><br /><i>Targeting an access point</i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss2.png" /><br /><i>A successful attack</i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss7.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/firmware-upgrade/">router configuration page</a></i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss6.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/oauth-login/">OAuth Login Page</a></i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss4.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/wifi_connect/">web-based network manager</a></i></p>

## 帮助
如果你是python开发者希望你来帮助 wifiphisher 不断完善. bug反馈 <a href="https://github.com/sophron/wifiphisher/issues">bug跟踪</a>.

如果你不会写代码 <a href="https://github.com/sophron/wifiphisher/issues">问题提交</a>. 可以参阅 <a href="https://github.com/sophron/wifiphisher/wiki/Bug-reporting-guidelines">bug反馈指南</a> 和 <a href="https://github.com/sophron/wifiphisher/wiki/Frequently-Asked-Questions-%28FAQ%29">FAQ 文档</a> .  请勿将工具用于非法用途.

## 认证
来自于<a href="https://github.com/DanMcInerney">Dan McInerney</a>的想法.

贡献者列表 <a href="https://github.com/sophron/wifiphisher/graphs/contributors">这里</a>.

## 许可协议
Wifiphisher 基于 GPL 许可. 查看 [LICENSE](LICENSE) 了解更多.

## 项目状态
`Wifiphisher` 当前版本 **1.2**. 你可以下载最新版 <a href="https://github.com/sophron/wifiphisher/releases/tag/v1.2">这里</a>.

## 免责声明
* 作者不承担任何责任，不因本程序造成的任何误用或损害负责。汉化版使用者同样适用下述条款！

* Authors do not own the logos under the `wifiphisher/data/` directory. Copyright Disclaimer Under Section 107 of the Copyright Act 1976, allowance is made for "fair use" for purposes such as criticism, comment, news reporting, teaching, scholarship, and research.

* Usage of Wifiphisher for attacking infrastructures without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.

<b>Note</b>: <a href="htts://wifiphisher.org">wifiphisher.org</a> and this page are the only official pages for wifiphisher. Other sites may be delivering malware.
[![alt text][1.1]][1]
[1.1]: http://i.imgur.com/tXSoThF.png (Follow me)
[1]: http://www.twitter.com/_sophron
