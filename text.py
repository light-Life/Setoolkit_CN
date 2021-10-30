#!/usr/bin/env python3
########################################################################
#
# text menu for set menu stuff
#
########################################################################
from src.core.setcore import bcolors, get_version, check_os, meta_path

# grab version of SET
define_version = get_version()

# check operating system
operating_system = check_os()

# grab metasploit path
msf_path = meta_path()

PORT_NOT_ZERO = "Port cannot be zero!"
PORT_TOO_HIGH = "Let's stick with the LOWER 65,535 ports..."

main_text = " Select from the menu:\n"

main_menu = ['Social-Engineering Attacks\033[0;36m【社工攻击\033[0;31m(常用)\033[0m\033[0;36m】\033[0m',
             'Penetration Testing (Fast-Track)\033[0;36m【渗透测试（快速的）】\033[0m',
             'Third Party Modules\033[0;36m【第三方模块】\033[0m',
             'Update the Social-Engineer Toolkit\033[0;36m【更新社工工具包】\033[0m',
             'Update SET configuration\033[0;36m【升级配置】\033[0m',
             'Help, Credits, and About\033[0;36m【帮助】\033[0m']

main = ['Spear-Phishing Attack Vectors\033[0;36m【鱼叉式网络钓鱼攻击】\033[0m',
        'Website Attack Vectors\033[0;36m【web网站式攻击-钓鱼\033[0;31m(常用)\033[0m\033[0;36m】\033[0m',
        'Infectious Media Generator\033[0;36m【传染性木马】\033[0m',
        'Create a Payload and Listener\033[0;36m【创建payload和监听器】\033[0m',
        'Mass Mailer Attack\033[0;36m【邮件群发攻击】\033[0m',
        'Arduino-Based Attack Vector\033[0;36m【基于安卓的攻击】\033[0m',
        'Wireless Access Point Attack Vector\033[0;36m【wifi攻击】\033[0m',
        'QRCode Generator Attack Vector\033[0;36m【生成二维码(就普通二维码)】\033[0m',
        'Powershell Attack Vectors\033[0;36m【Powershell攻击】\033[0m',
        'Third Party Modules\033[0;36m【第三方模块】\033[0m']

spearphish_menu = ['Perform a Mass Email Attack\033[0;36m【大规模邮件攻击】\033[0m',
                   'Create a FileFormat Payload\033[0;36m【创建文件载荷】\033[0m',
                   'Create a Social-Engineering Template\033[0;36m【创建社工模板】\033[0m',
                   '0D']

spearphish_text = ("""
 The """ + bcolors.BOLD + """Spearphishing""" + bcolors.ENDC + """ module allows you to specially craft email messages and send
 them to a large (or small) number of people with attached fileformat malicious
 payloads. If you want to spoof your email address, be sure "Sendmail" is in-
 stalled (apt-get install sendmail) and change the config/set_config SENDMAIL=OFF
 flag to SENDMAIL=ON.

 There are two options, one is getting your feet wet and letting SET do
 everything for you (option 1), the second is to create your own FileFormat
 payload and use it in your own attack. Either way, good luck and enjoy!
""")

webattack_menu = ['Java Applet Attack Method\033[0;36m【java小程序攻击】\033[0m',
                  'Metasploit Browser Exploit Method\033[0;36m【Metasploit浏览器利用】\033[0m',
                  'Credential Harvester Attack Method\033[0;36m【凭证攻击\033[0;31m(常用)\033[0m\033[0;36m】\033[0m',
                  'Tabnabbing Attack Method\033[0;36m【Tabnabbing攻击】\033[0m',
                  'Web Jacking Attack Method\033[0;36m【web劫持】\033[0m',
                  'Multi-Attack Web Method\033[0;36m【web多重攻击】\033[0m',
                  'HTA Attack Method\033[0;36m【HTA攻击】\033[0m',
                  '0D']

fasttrack_menu = ['Microsoft SQL Bruter\033[0;36m【应该是mssql暴力破解】\033[0m',
                  'Custom Exploits\033[0;36m【自定义exp】\033[0m',
                  'SCCM Attack Vector\033[0;36m【SCCM攻击】\033[0m',
                  'Dell DRAC/Chassis Default Checker\033[0;36m【DRAC/Chassis默认检测程序】\033[0m',
                  'RID_ENUM - User Enumeration Attack\033[0;36m【RID_ENUM-用户枚举】\033[0m',
                  'PSEXEC Powershell Injection\033[0;36m【PSEXEC Powershell注入】\033[0m',
                  '0D']

fasttrack_text = ("""
Welcome to the Social-Engineer Toolkit - """ + bcolors.BOLD + """Fast-Track Penetration Testing platform""" + bcolors.ENDC + """. These attack vectors
have a series of exploits and automation aspects to assist in the art of penetration testing. SET
now incorporates the attack vectors leveraged in Fast-Track. All of these attack vectors have been
completely rewritten and customized from scratch as to improve functionality and capabilities.
""")

fasttrack_exploits_menu1 = ['MS08-067 (Win2000, Win2k3, WinXP)\033[0;36m【和ms17-010应该都是我们的老朋友了】\033[0m',
                            'Mozilla Firefox 3.6.16 mChannel Object Use After Free Exploit (Win7)\033[0;36m【Firefox 3.6.16漏洞】\033[0m',
                            'Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit\033[0;36m【Manager 5.1.0远程系统SQL注入漏洞】\033[0m',
                            'RDP | Use after Free - Denial of Service\033[0;36m【RDP拒绝服务】\033[0m',
                            'MySQL Authentication Bypass Exploit\033[0;36m【mysql身份绕过】\033[0m',
                            'F5 Root Authentication Bypass Exploit\033[0;36m【root用户身份绕过】\033[0m',
                            '0D']

fasttrack_exploits_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Exploits Section""" + bcolors.ENDC + """. This
menu has obscure exploits and ones that are primarily python driven. This will continue to grow over time.
""")

fasttrack_mssql_menu1 = ['Scan and Attack MSSQL\033[0;36m【扫描并攻击mssql】\033[0m',
                         'Connect directly to MSSQL\033[0;36m【连接mssql】\033[0m',
                         '0D']

fasttrack_mssql_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Microsoft SQL Brute Forcer""" + bcolors.ENDC + """. This
attack vector will attempt to identify live MSSQL servers and brute force the weak account passwords that
may be found. If that occurs, SET will then compromise the affected system by deploying a binary to
hexadecimal attack vector which will take a raw binary, convert it to hexadecimal and use a staged approach
in deploying the hexadecimal form of the binary onto the underlying system. At this point, a trigger will occur
to convert the payload back to a binary for us.
""")

webattack_text = ("""
The Web Attack module is a unique way of utilizing multiple web-based attacks in order to compromise the intended victim.

The """ + bcolors.BOLD + """Java Applet Attack""" + bcolors.ENDC + """ method will spoof a Java Certificate and deliver a metasploit based payload. Uses a customized java applet created by Thomas Werth to deliver the payload.

The """ + bcolors.BOLD + """Metasploit Browser Exploit""" + bcolors.ENDC + """ method will utilize select Metasploit browser exploits through an iframe and deliver a Metasploit payload.

The """ + bcolors.BOLD + """Credential Harvester""" + bcolors.ENDC + """ method will utilize web cloning of a web- site that has a username and password field and harvest all the information posted to the website.

The """ + bcolors.BOLD + """TabNabbing""" + bcolors.ENDC + """ method will wait for a user to move to a different tab, then refresh the page to something different.

The """ + bcolors.BOLD + """Web-Jacking Attack""" + bcolors.ENDC + """ method was introduced by white_sheep, emgent. This method utilizes iframe replacements to make the highlighted URL link to appear legitimate however when clicked a window pops up then is replaced with the malicious link. You can edit the link replacement settings in the set_config if its too slow/fast.

The """ + bcolors.BOLD + """Multi-Attack""" + bcolors.ENDC + """ method will add a combination of attacks through the web attack menu. For example you can utilize the Java Applet, Metasploit Browser, Credential Harvester/Tabnabbing all at once to see which is successful.

The """ + bcolors.BOLD + """HTA Attack""" + bcolors.ENDC + """ method will allow you to clone a site and perform powershell injection through HTA files which can be used for Windows-based powershell exploitation through the browser.
""")

webattack_vectors_menu = ['Web Templates\033[0;36m【web模板】\033[0m',
                          'Site Cloner\033[0;36m【克隆网站】\033[0m',
                          'Custom Import\033[0;36m【自定义导入】\033[0m\n',
                          ]

webattack_vectors_text = ("""
 The first method will allow SET to import a list of pre-defined web
 applications that it can utilize within the attack.

 The second method will completely clone a website of your choosing
 and allow you to utilize the attack vectors within the completely
 same web application you were attempting to clone.

 The third method allows you to import your own website, note that you
 should only have an index.html when using the import website
 functionality.
   """)

teensy_menu = ['Powershell HTTP GET MSF Payload\033[0;36m【Powershell通过GET(http)的形式获取msf-payload】\033[0m',
               'WSCRIPT HTTP GET MSF Payload\033[0;36m【WSCRIPT通过GET(http)的形式获取msf-payload】\033[0m',
               'Powershell based Reverse Shell Payload\033[0;36m【Powershell反向payload】\033[0m',
               'Internet Explorer/FireFox Beef Jack Payload\033[0;36m【Internet-FireFox payload】\033[0m',
               'Go to malicious java site and accept applet Payload\033[0;36m【转到恶意java站点】\033[0m',
               'Gnome wget Download Payload\033[0;36m【利用wget下载载荷】\033[0m',
               'Binary 2 Teensy Attack (Deploy MSF payloads)\033[0;36m【二进制 Teensy攻击（部署MSF有效负载）】\033[0m',
               'SDCard 2 Teensy Attack (Deploy Any EXE)\033[0;36m【SDCard Teensy攻击（部署任何EXE）】\033[0m',
               'SDCard 2 Teensy Attack (Deploy on OSX)\033[0;36m【SD卡攻击（部署在OSX上）】\033[0m',
               'X10 Arduino Sniffer PDE and Libraries\033[0;36m【X10 Arduino嗅探器-PDE和库】\033[0m',
               'X10 Arduino Jammer PDE and Libraries\033[0;36m【X10 Arduino干扰机-PDE和库】\033[0m',
               'Powershell Direct ShellCode Teensy Attack\033[0;36m【Powershell攻击】\033[0m',
               'Peensy Multi Attack Dip Switch + SDCard Attack\033[0;36m【PENENSY多重攻击Dip开关+SD卡攻击】\033[0m',
	           'HID Msbuild compile to memory Shellcode Attack\033[0;36m【HID Msbuild编译到内存攻击】\033[0m',
               '0D']

teensy_text = ("""
 The """ + bcolors.BOLD + """Arduino-Based Attack""" + bcolors.ENDC + """ Vector utilizes the Arduin-based device to
 program the device. You can leverage the Teensy's, which have onboard
 storage and can allow for remote code execution on the physical
 system. Since the devices are registered as USB Keyboard's it
 will bypass any autorun disabled or endpoint protection on the
 system.

 You will need to purchase the Teensy USB device, it's roughly
 $22 dollars. This attack vector will auto generate the code
 needed in order to deploy the payload on the system for you.

 This attack vector will create the .pde files necessary to import
 into Arduino (the IDE used for programming the Teensy). The attack
 vectors range from Powershell based downloaders, wscript attacks,
 and other methods.

 For more information on specifications and good tutorials visit:

 http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle

 To purchase a Teensy, visit: http://www.pjrc.com/store/teensy.html
 Special thanks to: IronGeek, WinFang, and Garland

 This attack vector also attacks X10 based controllers, be sure to be leveraging
 X10 based communication devices in order for this to work.

 Select a payload to create the pde file to import into Arduino:
""")

wireless_attack_menu = ['Start the SET Wireless Attack Vector Access Point',
                        'Stop the SET Wireless Attack Vector Access Point',
                        '0D']


wireless_attack_text = """
 The """ + bcolors.BOLD + """Wireless Attack""" + bcolors.ENDC + """ module will create an access point leveraging your
 wireless card and redirect all DNS queries to you. The concept is fairly
 simple, SET will create a wireless access point, dhcp server, and spoof
 DNS to redirect traffic to the attacker machine. It will then exit out
 of that menu with everything running as a child process.

 You can then launch any SET attack vector you want, for example the Java
 Applet attack and when a victim joins your access point and tries going to
 a website, will be redirected to your attacker machine.

 This attack vector requires AirBase-NG, AirMon-NG, DNSSpoof, and dhcpd3.

"""

infectious_menu = ['File-Format Exploits\033[0;36m【文件格式漏洞】\033[0m',
                   'Standard Metasploit Executable\033[0;36m【生成标准Metasploit-exp（就是msf生成的那个exp）】\033[0m',
                   '0D']


infectious_text = """
 The """ + bcolors.BOLD + bcolors.GREEN + """Infectious """ + bcolors.ENDC + """USB/CD/DVD module will create an autorun.inf file and a
 Metasploit payload. When the DVD/USB/CD is inserted, it will automatically
 run if autorun is enabled.""" + bcolors.ENDC + """

 Pick the attack vector you wish to use: fileformat bugs or a straight executable.
"""

# used in create_payloads.py
if operating_system != "windows":
    if msf_path != False:
        payload_menu_1 = [
            'Meterpreter Memory Injection (DEFAULT)  This will drop a meterpreter payload through powershell injection',
            'Meterpreter Multi-Memory Injection      This will drop multiple Metasploit payloads via powershell injection',
            'SE Toolkit Interactive Shell            Custom interactive reverse toolkit designed for SET',
            'SE Toolkit HTTP Reverse Shell           Purely native HTTP shell with AES encryption support',
            'RATTE HTTP Tunneling Payload            Security bypass payload that will tunnel all comms over HTTP',
            'ShellCodeExec Alphanum Shellcode        This will drop a meterpreter payload through shellcodeexec',
            'Import your own executable              Specify a path for your own executable',
            'Import your own commands.txt            Specify payloads to be sent via command line\n']

if operating_system == "windows" or msf_path == False:
    payload_menu_1 = [
        'SE Toolkit Interactive Shell    Custom interactive reverse toolkit designed for SET',
        'SE Toolkit HTTP Reverse Shell   Purely native HTTP shell with AES encryption support',
        'RATTE HTTP Tunneling Payload    Security bypass payload that will tunnel all comms over HTTP\n']

payload_menu_1_text = """
What payload do you want to generate:

  Name:                                       Description:
"""

# used in gen_payload.py
payload_menu_2 = [
    'Windows Shell Reverse_TCP               Spawn a command shell on victim and send back to attacker\033[0;36m【windows-TCP反向连接】\033[0m',
    'Windows Reverse_TCP Meterpreter         Spawn a meterpreter shell on victim and send back to attacker\033[0;36m【windows反向链接后渗透】\033[0m',
    'Windows Reverse_TCP VNC DLL             Spawn a VNC server on victim and send back to attacker\033[0;36m【windows-TCP反向连接，shell为dll格式】\033[0m',
    'Windows Shell Reverse_TCP X64           Windows X64 Command Shell, Reverse TCP Inline\033[0;36m【windows 64位-TCP反向连接】\033[0m',
    'Windows Meterpreter Reverse_TCP X64     Connect back to the attacker (Windows x64), Meterpreter\033[0;36m【windows 64位反向链接后渗透模式】\033[0m',
    'Windows Meterpreter Egress Buster       Spawn a meterpreter shell and find a port home via multiple ports\033[0;36m【这个不是很懂，说的是啥通过一个端口找其他端口】\033[0m',
    'Windows Meterpreter Reverse HTTPS       Tunnel communication over HTTP using SSL and use Meterpreter\033[0;36m【windows HTTPS式的反向连接】\033[0m',
    'Windows Meterpreter Reverse DNS         Use a hostname instead of an IP address and use Reverse Meterpreter\033[0;36m【windows DNS式的反向连接】\033[0m',
    'Download/Run your Own Executable        Downloads an executable and runs it\033[0;36m【下载一个可执行文件并运行(应该是目标机，比如我们下载并运行个猕猴桃，hash值和明文不就出来了吗)】\033[0m\n'
]


payload_menu_2_text = """\n"""

payload_menu_3_text = ""
payload_menu_3 = [
    'Windows Reverse TCP Shell              Spawn a command shell on victim and send back to attacker',
    'Windows Meterpreter Reverse_TCP        Spawn a meterpreter shell on victim and send back to attacker',
    'Windows Reverse VNC DLL                Spawn a VNC server on victim and send back to attacker',
    'Windows Reverse TCP Shell (x64)        Windows X64 Command Shell, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP (X64)  Connect back to the attacker (Windows x64), Meterpreter',
    'Windows Shell Bind_TCP (X64)           Execute payload and create an accepting port on remote system',
    'Windows Meterpreter Reverse HTTPS      Tunnel communication over HTTP using SSL and use Meterpreter\n']

# called from create_payload.py associated dictionary = ms_attacks
create_payloads_menu = [
    'SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)\033[0;36m【设置自定义DLL劫持】\033[0m',
    'SET Custom Written Document UNC LM SMB Capture Attack\033[0;36m【设置自定义文件UNC LM SMB捕获攻击】\033[0m',
    'MS15-100 Microsoft Windows Media Center MCL Vulnerability\033[0;36m【MS15-100漏洞：Media Center远程代码执行】\033[0m',
    'MS14-017 Microsoft Word RTF Object Confusion (2014-04-01)\033[0;36m【MS14-017漏洞：Microsoft Word转换存在远程代码执行】\033[0m',
    'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow\033[0;36m【CreateSizedDIBSECTION缓冲区溢出】\033[0m',
    'Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)\033[0;36m【RTF缓冲区溢出】\033[0m',
    'Adobe Flash Player "Button" Remote Code Execution\033[0;36m【Flash远程代码执行】\033[0m',
    'Adobe CoolType SING Table "uniqueName" Overflow\033[0;36m【uniqueName溢出】\033[0m',
    'Adobe Flash Player "newfunction" Invalid Pointer Use\033[0;36m【Flash指针无法识别】\033[0m',
    'Adobe Collab.collectEmailInfo Buffer Overflow\033[0;36m【Collab.collectEmailInfo() 缓冲区溢出漏洞】\033[0m',
    'Adobe Collab.getIcon Buffer Overflow\033[0;36m【Collab.getIcon缓冲区溢出】\033[0m',
    'Adobe JBIG2Decode Memory Corruption Exploit\033[0;36m【JBIG2Decode内存损坏】\033[0m',
    'Adobe PDF Embedded EXE Social Engineering\033[0;36m【PDF嵌入EXE社工攻击】\033[0m',
    'Adobe util.printf() Buffer Overflow\033[0;36m【util.printf()缓冲区溢出】\033[0m',
    'Custom EXE to VBA (sent via RAR) (RAR required)\033[0;36m【自定义EXE发送到VBA(发送RAR文件)(需要RAR文件)】\033[0m',
    'Adobe U3D CLODProgressiveMeshDeclaration Array Overrun\033[0;36m【U3D CLODProgressiveMeshDeclaration数组溢出】\033[0m',
    'Adobe PDF Embedded EXE Social Engineering (NOJS)\033[0;36m【PDF嵌入EXE社工攻击（NOjs形式）】\033[0m',
    'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow\033[0;36m【Foxit PDF Reader v4.1.1缓冲区溢出】\033[0m',
    'Apple QuickTime PICT PnSize Buffer Overflow\033[0;36m【Apple QuickTime PICT PnSize缓冲区溢出】\033[0m',
    'Nuance PDF Reader v6.0 Launch Stack Buffer Overflow\033[0;36m【Nuance PDF Reader v6.0缓冲区溢出】\033[0m',
    'Adobe Reader u3D Memory Corruption Vulnerability\033[0;36m【Reader u3D内存损坏漏洞】\033[0m',
    'MSCOMCTL ActiveX Buffer Overflow (ms12-027)\033[0;36m【ms12-027：windows控件远程代码执行】\033[0m\n']

create_payloads_text = """
 Select the file format exploit you want.
 The default is the PDF embedded EXE.\n
           ********** PAYLOADS **********\n"""

browser_exploits_menu = [
    'Adobe Flash Player ByteArray Use After Free (2015-07-06)',
    'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow (2015-06-23)',
    'Adobe Flash Player Drawing Fill Shader Memory Corruption (2015-05-12)',
    'MS14-012 Microsoft Internet Explorer TextRange Use-After-Free (2014-03-11)',
    'MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free (2014-02-13)',
    'Internet Explorer CDisplayPointer Use-After-Free (10/13/2013)',
    'Micorosft Internet Explorer SetMouseCapture Use-After-Free (09/17/2013)',
    'Java Applet JMX Remote Code Execution (UPDATED 2013-01-19)',
    'Java Applet JMX Remote Code Execution (2013-01-10)',
    'MS13-009 Microsoft Internet Explorer SLayoutRun Use-AFter-Free (2013-02-13)',
    'Microsoft Internet Explorer CDwnBindInfo Object Use-After-Free (2012-12-27)',
    'Java 7 Applet Remote Code Execution (2012-08-26)',
    'Microsoft Internet Explorer execCommand Use-After-Free Vulnerability (2012-09-14)',
    'Java AtomicReferenceArray Type Violation Vulnerability (2012-02-14)',
    'Java Applet Field Bytecode Verifier Cache Remote Code Execution (2012-06-06)',
    'MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption (2012-06-12)',
    'Microsoft XML Core Services MSXML Uninitialized Memory Corruption (2012-06-12)',
    'Adobe Flash Player Object Type Confusion  (2012-05-04)',
    'Adobe Flash Player MP4 "cprt" Overflow (2012-02-15)',
    'MS12-004 midiOutPlayNextPolyEvent Heap Overflow (2012-01-10)',
    'Java Applet Rhino Script Engine Remote Code Execution (2011-10-18)',
    'MS11-050 IE mshtml!CObjectElement Use After Free  (2011-06-16)',
    'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability (2011-04-11)',
    'Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute (2011-06-01)',
    'Internet Explorer CSS Import Use After Free (2010-11-29)',
    'Microsoft WMI Administration Tools ActiveX Buffer Overflow (2010-12-21)',
    'Internet Explorer CSS Tags Memory Corruption (2010-11-03)',
    'Sun Java Applet2ClassLoader Remote Code Execution (2011-02-15)',
    'Sun Java Runtime New Plugin docbase Buffer Overflow (2010-10-12)',
    'Microsoft Windows WebDAV Application DLL Hijacker (2010-08-18)',
    'Adobe Flash Player AVM Bytecode Verification Vulnerability (2011-03-15)',
    'Adobe Shockwave rcsL Memory Corruption Exploit (2010-10-21)',
    'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow (2010-09-07)',
    'Apple QuickTime 7.6.7 Marshaled_pUnk Code Execution (2010-08-30)',
    'Microsoft Help Center XSS and Command Execution (2010-06-09)',
    'Microsoft Internet Explorer iepeers.dll Use After Free (2010-03-09)',
    'Microsoft Internet Explorer "Aurora" Memory Corruption (2010-01-14)',
    'Microsoft Internet Explorer Tabular Data Control Exploit (2010-03-0)',
    'Microsoft Internet Explorer 7 Uninitialized Memory Corruption (2009-02-10)',
    'Microsoft Internet Explorer Style getElementsbyTagName Corruption (2009-11-20)',
    'Microsoft Internet Explorer isComponentInstalled Overflow (2006-02-24)',
    'Microsoft Internet Explorer Explorer Data Binding Corruption (2008-12-07)',
    'Microsoft Internet Explorer Unsafe Scripting Misconfiguration (2010-09-20)',
    'FireFox 3.5 escape Return Value Memory Corruption (2009-07-13)',
    'FireFox 3.6.16 mChannel use after free vulnerability (2011-05-10)',
    'Metasploit Browser Autopwn (USE AT OWN RISK!)\n']

browser_exploits_text = """
 Enter the browser exploit you would like to use [8]:
"""

# this is for the powershell attack vectors
powershell_menu = ['Powershell Alphanumeric Shellcode Injector\033[0;36m【Powershell字母数字代码注入】\033[0m',
                   'Powershell Reverse Shell\033[0;36m【Powershell反向连接】\033[0m',
                   'Powershell Bind Shell\033[0;36m【Powershell正向连接】\033[0m',
                   'Powershell Dump SAM Database\033[0;36m【Powershell转储SAM数据库】\033[0m',
                   '0D']

powershell_text = ("""
The """ + bcolors.BOLD + """Powershell Attack Vector""" + bcolors.ENDC + """ module allows you to create PowerShell specific attacks. These attacks will allow you to use PowerShell which is available by default in all operating systems Windows Vista and above. PowerShell provides a fruitful  landscape for deploying payloads and performing functions that  do not get triggered by preventative technologies.\n""")


encoder_menu = ['shikata_ga_nai',
                'No Encoding',
                'Multi-Encoder',
                'Backdoored Executable\n']

encoder_text = """
Select one of the below, 'backdoored executable' is typically the best. However,
most still get picked up by AV. You may need to do additional packing/crypting
in order to get around basic AV detection.
"""

dll_hijacker_text = """
 The DLL Hijacker vulnerability will allow normal file extenstions to
 call local (or remote) .dll files that can then call your payload or
 executable. In this scenario it will compact the attack in a zip file
 and when the user opens the file extension, will trigger the dll then
 ultimately our payload. During the time of this release, all of these
 file extensions were tested and appear to work and are not patched. This
 will continiously be updated as time goes on.
"""

fakeap_dhcp_menu = ['10.0.0.100-254',
                    '192.168.10.100-254\n']

fakeap_dhcp_text = "Please choose which DHCP Config you would like to use: "
