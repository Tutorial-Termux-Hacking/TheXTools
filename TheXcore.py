#### Di recode nyawa anda melayang:V
###  Ngotak lah saya aja mikir:V
##  SUBSCRIBE DULU.NANTI BOLEH KALO MAU DI RECODE:V
# CHANNEL The X Queens
import json , sys
import hashlib , os , time , marshal, getpass

################################################
#               Warna Yang saya pake
A = '\033[036m'
B = '\033[034m'

TheXTools_banner = A+ '''
         _____ _         __  __    
        /__   \ |__   ___\ \/ /     
          / /\/ '_ \ / _ \\   /      
         / /  | | | |  __//  \      
         \/   |_| |_|\___/_/\_\    
                               
                     _____            _     
                    /__   \___   ___ | |___      
                      / /\/ _ \ / _ \| / __|    
                     / / | (_) | (_) | \__ \   
                     \/   \___/ \___/|_|___/     
[]Tools Installer[]
[*]Tools untuk mempermudah menggunakan Tools[*]
{}Gunakan dengan bijak{}
[* Kode By The X Queens *]
'''

backtomenu_banner = B+ """
  [99] Kembali ke menu
  [00] Keluar dari tools
"""

def restart_program():
	python = sys.executable
	os.execl(python, python, * sys.argv)
	curdir = os.getcwd()

def backtomenu_option():
	print backtomenu_banner
	backtomenu = raw_input("TheX > ")
	
	if backtomenu == "99":
		restart_program()
	elif backtomenu == "00":
		sys.exit()
	else:
		print "\nERROR: Salah ngetik"
		time.sleep(2)
		restart_program()

def banner():
	print TheXTools_banner

def nmap():
	print '\n###### Menginstall Nmap'
	os.system('apt update && apt upgrade')
	os.system('apt install nmap')
	print '###### Berhasil'
	print "###### Tools 'nmap' Siap di gunakan."
	backtomenu_option()

def red_hawk():
	print '\n###### Menginstall RED HAWK'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone https://github.com/Tuhinshubhra/RED_HAWK')
	os.system('mv RED_HAWK ~')
	print '###### RED_HAWK Berhasil Di Install'
	backtomenu_option()

def dtect():
	print '\n###### Menginstall D-Tect'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/bibortone/D-Tech')
	os.system('mv D-Tect ~')
	print '###### D-Tect Berhasil Di Install'
	backtomenu_option()

def sqlmap():
	print '\n###### Menginstall sqlmap'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/sqlmapproject/sqlmap')
	os.system('mv sqlmap ~')
	print '###### sqlmal Berhasil Di Install'
	backtomenu_option()

def infoga():
	print '\n###### Menginstall Infoga'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install requests urllib3 urlparse')
	os.system('git clone https://github.com/m4ll0k/Infoga')
	os.system('mv Infoga ~')
	print '###### Infoga Berhasil Di Install'
	backtomenu_option()

def reconDog():
	print '\n###### Menginstall ReconDog'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/UltimateHackers/ReconDog')
	os.system('mv ReconDog ~')
	print '###### ReconDog Berhasil Di Install'
	backtomenu_option()

def androZenmap():
	print '\n###### Menginstall AndroZenmap'
	os.system('apt update && apt upgrade')
	os.system('apt install nmap curl')
	os.system('curl -O https://raw.githubusercontent.com/Gameye98/Gameye98.github.io/master/scripts/androzenmap.sh')
	os.system('mkdir ~/AndroZenmap')
	os.system('mv androzenmap.sh ~/AndroZenmap')
	print '###### AndroZemap Berhasil Di Install'
	backtomenu_option()

def sqlmate():
	print '\n###### Menginstall  sqlmate'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install mechanize bs4 HTMLparser argparse requests urlparse2')
	os.system('git clone https://github.com/UltimateHackers/sqlmate')
	os.system('mv sqlmate ~')
	print '###### sqlmate Berhasil Di Install'
	backtomenu_option()

def astraNmap():
	print '\n###### Menginstall AstraNmap'
	os.system('apt update && apt upgrade')
	os.system('apt install git nmap')
	os.system('git clone https://github.com/Gameye98/AstraNmap')
	os.system('mv AstraNmap ~')
	print '###### AstraNmap Berhasil Di Install'
	backtomenu_option()

def wtf():
	print '\n###### Menginstall WTF'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip bs4 requests HTMLParser urlparse mechanize argparse')
	os.system('git clone https://github.com/Xi4u7/wtf')
	os.system('mv wtf ~')
	print '###### WTF Berhasil Di Install'
	backtomenu_option()

def easyMap():
	print '\n###### Menginstall Easymap'
	os.system('apt update && apt upgrade')
	os.system('apt install php git')
	os.system('git clone https://github.com/Cvar1984/Easymap')
	os.system('mv Easymap ~')
	os.system('cd ~/Easymap && sh install.sh')
	print '###### Easymap Berhasil Di Install'
	backtomenu_option()

def xd3v():
	print '\n###### Menginstall XD3v'
	os.system('apt update && apt upgrade')
	os.system('apt install curl')
	os.system('curl -k -O https://gist.github.com/Gameye98/92035588bd0228df6fb7fa77a5f26bc2/raw/f8e73cd3d9f2a72bd536087bb6ba7bc8baef7d1d/xd3v.sh')
	os.system('mv xd3v.sh ~/../usr/bin/xd3v && chmod +x ~/../usr/bin/xd3v')
	print '###### XD3v Berhasil Di Install'
	print "###### Type 'xd3v' to start."
	backtomenu_option()

def crips():
	print '\n###### Menginstall Crips'
	os.system("apt update && apt upgrade")
	os.system("apt install git python2 openssl curl libcurl wget")
	os.system("git clone https://github.com/Manisso/Crips")
	os.system("mv Crips ~")
	print '###### Crips Berhasil Di Install'
	backtomenu_option()

def sir():
	print '\n###### Menginstall SIR'
	os.system("apt update && apt upgrade")
	os.system("apt install python2 git")
	os.system("python2 -m pip install bs4 urllib2")
	os.system("git clone https://github.com/AeonDave/sir.git")
	os.system("mv sir ~")
	print '###### SIR Berhasil Di Install'
	backtomenu_option()

def xshell():
	print '\n###### Menginstall Xshell'
	os.system("apt update && apt upgrade")
	os.system("apt install lynx python2 figlet ruby php nano w3m")
	os.system("git clone https://github.com/Ubaii/Xshell")
	os.system("mv Xshell ~")
	print '###### Xshell Berhasil Di Install'
	backtomenu_option()

def evilURL():
	print '\n###### Menginstall EvilURL'
	os.system("apt update && apt upgrade")
	os.system("apt install git python2 python3")
	os.system("git clone https://github.com/UndeadSec/EvilURL")
	os.system("mv EvilURL ~")
	print '###### EvilURL Berhasil Di Install'
	backtomenu_option()

def striker():
	print '\n###### Menginstall Striker'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/UltimateHackers/Striker')
	os.system('mv Striker ~')
	os.system('cd ~/Striker && python2 -m pip install -r requirements.txt')
	print '###### Striker Berhasil Di Install'
	backtomenu_option()

def dsss():
	print '\n###### Menginstall DSSS'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/stamparm/DSSS')
	os.system('mv DSSS ~')
	print '###### DSSS Berhasil Di Install'
	backtomenu_option()

def sqliv():
	print '\n###### Menginstall SQLiv'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/Hadesy2k/sqliv')
	os.system('mv sqliv ~')
	print '###### SQLiv Berhasil Di Install'
	backtomenu_option()

def sqlscan():
	print '\n###### Menginstall sqlscan'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone http://www.github.com/Cvar1984/sqlscan')
	os.system('mv sqlscan ~')
	print '###### sqlscan Berhasil Di Install'
	backtomenu_option()

def wordpreSScan():
	print '\n###### Menginstall Wordpresscan'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 python2-dev clang libxml2-dev libxml2-utils libxslt-dev')
	os.system('git clone https://github.com/swisskyrepo/Wordpresscan')
	os.system('mv Wordpresscan ~')
	os.system('cd ~/Wordpresscan && python2 -m pip install -r requirements.txt')
	print '###### Wordpresscan Berhasil Di Install'
	backtomenu_option()

def wpscan():
	print '\n###### Menginstall WPScan'
	os.system('apt update && apt upgrade')
	os.system('apt install git ruby curl')
	os.system('git clone https://github.com/wpscanteam/wpscan')
	os.system('mv wpscan ~ && cd ~/wpscan')
	os.system('gem install bundle && bundle config build.nokogiri --use-system-libraries && bundle install && ruby wpscan.rb --update')
	print '###### WPScan Berhasil Di Install'
	backtomenu_option()

def wordpresscan():
	print '\n###### Menginstall wordpresscan(2)'
	os.system('apt update && apt upgrade')
	os.system('apt install nmap figlet git')
	os.system('git clone https://github.com/silverhat007/termux-wordpresscan')
	os.system('cd termux-wordpresscan && chmod +x * && sh install.sh')
	os.system('mv termux-wordpresscan ~')
	print '###### wordpresscan Berhasil Di Install'
	print "###### Gunakan Command 'wordpresscan' Untuk Masuk Tools."
	backtomenu_option()

def routersploit():
	print '\n###### Menginstall Routersploit'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/reverse-shell/routersploit')
	os.system('mv routersploit ~;cd ~/routersploit;python2 -m pip install -r requirements.txt;termux-fix-shebang rsf.py')
	print '###### Routersploit Berhasil Di Install'
	backtomenu_option()

def torshammer():
	print '\n###### Menginstall Torshammer'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/dotfighter/torshammer')
	os.system('mv torshammer ~')
	print '###### Torshammer Berhasil Di Install'
	backtomenu_option()

def slowloris():
	print '\n###### Menginstall Slowloris'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/gkbrk/slowloris')
	os.system('mv slowloris ~')
	print '###### Slowloris Berhasil Di Install'
	backtomenu_option()

def fl00d12():
	print '\n###### Menginstall Fl00d & Fl00d2'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 curl')
	os.system('mkdir ~/fl00d')
	os.system('curl -O https://raw.githubusercontent.com/Gameye98/Gameye98.github.io/master/scripts/fl00d.py')
	os.system('curl -O https://raw.githubusercontent.com/Gameye98/Gameye98.github.io/master/scripts/fl00d2.py')
	os.system('mv fl00d.py ~/fl00d && mv fl00d2.py ~/fl00d')
	print '###### F100d & F100d2 Berhasil Di Install'
	backtomenu_option()

def goldeneye():
	print '\n###### Menginstall GoldenEye'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/jseidl/GoldenEye')
	os.system('mv GoldenEye ~')
	print '###### GoldenEye Berhasil Di Install'
	backtomenu_option()

def xerxes():
	print '\n###### Menginstall Xerxes'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('apt install clang')
	os.system('git clone https://github.com/zanyarjamal/xerxes')
	os.system('mv xerxes ~')
	os.system('cd ~/xerxes && clang xerxes.c -o xerxes')
	print '###### Xerxes Berhasil Di Install'
	backtomenu_option()

def planetwork_ddos():
	print '\n###### Menginstall Planetwork-DDOS'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/Hydra7/Planetwork-DDOS')
	os.system('mv Planetwork-DDOS ~')
	print '###### Planetwork-DDOS Berhasil Di Install'
	backtomenu_option()

def hydra():
	print '\n###### Menginstall Hydra'
	os.system('apt update && apt upgrade')
	os.system('apt install hydra')
	print '###### Hydra Berhasil Di Install'
	backtomenu_option()

def black_hydra():
	print '\n###### Menginstall Black Hydra'
	os.system('apt update && apt upgrade')
	os.system('apt install hydra git python2')
	os.system('git clone https://github.com/Gameye98/Black-Hydra')
	os.system('mv Black-Hydra ~')
	print '###### Black Hydra Berhasil Di Install'
	backtomenu_option()

def cupp():
	print '\n###### Menginstall Cupp'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/Mebus/cupp')
	os.system('mv cupp ~')
	print '###### Cupp Berhasil Di Install'
	backtomenu_option()

def asu():
	print '\n###### Menginstall ASU'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 php')
	os.system('python2 -m pip install requests bs4 mechanize')
	os.system('git clone https://github.com/LOoLzeC/ASU')
	os.system('mv ASU ~')
	print '###### ASU Berhasil Di Install'
	backtomenu_option()

def hash_buster():
	print '\n###### Menginstall Hash-Buster'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/UltimateHackers/Hash-Buster')
	os.system('mv Hash-Buster ~')
	print '###### Hash-Buster Berhasil Di Install'
	backtomenu_option()

def instaHack():
	print '\n###### Menginstall InstaHack'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/avramit/instahack')
	os.system('mv instahack ~')
	print '###### InstaHack Berhasil Di Install'
	backtomenu_option()

def indonesian_wordlist():
	print '\n###### Menginstall indonesian-wordlist'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/geovedi/indonesian-wordlist')
	os.system('mv indonesian-wordlist ~')
	print '###### Indonesian-wordlist Berhasil Di Install'
	backtomenu_option()

def fbBrute():
	print '\n###### Menginstall Facebook Brute Force 3'
	os.system('apt update && apt upgrade')
	os.system('apt install curl python2')
	os.system('python2 -m pip install mechanize')
	os.system('curl -O https://raw.githubusercontent.com/Gameye98/Gameye98.github.io/master/scripts/facebook3.py')
	os.system('curl -O https://raw.githubusercontent.com/Gameye98/Gameye98.github.io/master/wordlist/password.txt')
	os.system('mkdir ~/facebook-brute-3')
	os.system('mv facebook3.py ~/facebook-brute-3 && mv password.txt ~/facebook-brute-3')
	print '###### Facebook Brute Force 3 Berhasil Di Install'
	backtomenu_option()

def webdav():
	print '\n###### Menginstall Webdav'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 openssl curl libcurl')
	os.system('python2 -m pip install urllib3 chardet certifi idna requests')
	os.system('mkdir ~/webdav')
	os.system('curl -k -O http://override.waper.co/files/webdav.txt;mv webdav.txt ~/webdav/webdav.py')
	print '###### Webdav Berhasil Di Install'
	backtomenu_option()

def xGans():
	print '\n###### Menginstall xGans'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 curl')
	os.system('mkdir ~/xGans')
	os.system('curl -O http://override.waper.co/files/xgans.txt')
	os.system('mv xgans.txt ~/xGans/xgans.py')
	print '###### xGans Berhasil Di Install'
	backtomenu_option()

def webmassploit():
	print '\n###### Menginstall Webdav Mass Exploiter'
	os.system("apt update && apt upgrade")
	os.system("apt install python2 openssl curl libcurl")
	os.system("python2 -m pip install requests")
	os.system("curl -k -O https://pastebin.com/raw/K1VYVHxX && mv K1VYVHxX webdav.py")
	os.system("mkdir ~/webdav-mass-exploit && mv webdav.py ~/webdav-mass-exploit")
	print '###### Webdav Mass Exploiter Berhasil Di Install'
	backtomenu_option()

def wpsploit():
	print '\n###### Menginstall WPSploit'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone git clone https://github.com/m4ll0k/wpsploit')
	os.system('mv wpsploit ~')
	print '###### WPSploit Berhasil Di Install'
	backtomenu_option()

def sqldump():
	print '\n###### Menginstall sqldump'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 curl')
	os.system('python2 -m pip install google')
	os.system('curl -k -O https://gist.githubusercontent.com/Gameye98/76076c9a282a6f32749894d5368024a6/raw/6f9e754f2f81ab2b8efda30603dc8306c65bd651/sqldump.py')
	os.system('mkdir ~/sqldump && chmod +x sqldump.py && mv sqldump.py ~/sqldump')
	print '###### sqldump Berhasil Di Install'
	backtomenu_option()

def websploit():
	print '\n###### Menginstall Websploit'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install scapy')
	os.system('git clone https://github.com/The404Hacking/websploit')
	os.system('mv websploit ~')
	print '###### Websploit Berhasil Di Install'
	backtomenu_option()

def sqlokmed():
	print '\n###### Menginstall sqlokmed'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install urllib2')
	os.system('git clone https://github.com/Anb3rSecID/sqlokmed')
	os.system('mv sqlokmed ~')
	print '###### sqlokmed Berhasil Di Install'
	backtomenu_option()

def zones():
	print '\n###### Menginstall zones'
	os.system("apt update && apt upgrade")
	os.system("apt install git php")
	os.system("git clone https://github.com/Cvar1984/zones")
	os.system("mv zones ~")
	print '###### zones Berhasil Di Install'
	backtomenu_option()

def metasploit():
	print '\n###### Menginstall Metasploit'
	os.system("apt update && apt upgrade")
	os.system("apt install unstable-repo")
	os.system("cd ~ && apt install metasploit")
	print '###### Metasploit Berhasil Di Install'
	print "###### Gunakan Command 'msfconsole' Untuk Masuk Tools."
	backtomenu_option()

def commix():
	print '\n###### Menginstall Commix'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/commixproject/commix')
	os.system('mv commix ~')
	print '###### Commix Berhasil Di Install'
	backtomenu_option()

def brutal():
	print '\n###### Menginstall Brutal'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/Screetsec/Brutal')
	os.system('mv Brutal ~')
	print '###### Brutal Berhasil Di Install'
	backtomenu_option()

def a_rat():
	print '\n###### Menginstall A-Rat'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/Xi4u7/A-Rat')
	os.system('mv A-Rat ~')
	print '###### A-Rat Berhasil Di Install'
	backtomenu_option()

def knockmail():
	print '\n###### Menginstall KnockMail'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('python2 -m pip install validate_email pyDNS')
	os.system('git clone https://github.com/4w4k3/KnockMail')
	os.system('mv KnockMail ~')
	print '###### KnockMail Berhasil Di Install'
	backtomenu_option()

def spammer_grab():
	print '\n###### Menginstall Spammer-Grab'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git && python2 -m pip install requests')
	os.system('git clone https://github.com/p4kl0nc4t/spammer-grab')
	os.system('mv spammer-grab ~')
	print '###### Spanmer-Grab Berhasil Di Install'
	backtomenu_option()

def hac():
	print '\n###### Menginstall Hac'
	os.system('apt update && apt upgrade')
	os.system('apt install php git')
	os.system('git clone https://github.com/Cvar1984/Hac')
	os.system('mv Hac ~')
	print '###### Hac Berhasil Di Install'
	backtomenu_option()

def spammer_email():
	print '\n###### Menginstall Spammer-Email'
	os.system("apt update && apt upgrade")
	os.system("apt install git python2 && python2 -m pip install argparse requests")
	os.system("git clone https://github.com/p4kl0nc4t/Spammer-Email")
	os.system("mv Spammer-Email ~")
	print '###### Spammer-Email Berhasil Di Install'
	backtomenu_option()

def rang3r():
	print '\n###### Menginstall Rang3r'
	os.system("apt update && apt upgrade")
	os.system("apt install git python2 && python2 -m pip install optparse termcolor")
	os.system("git clone https://github.com/floriankunushevci/rang3r")
	os.system("mv rang3r ~")
	print '###### Rang3r Berhasil Di Install'
	backtomenu_option()

def sh33ll():
	print '\n###### Menginstall SH33LL'
	os.system("apt update && apt upgrade")
	os.system("apt install git python2")
	os.system("git clone https://github.com/LOoLzeC/SH33LL")
	os.system("mv SH33LL ~")
	print '###### SH33LL Berhasil Di Install '
	backtomenu_option()

def social():
	print '\n###### Menginstall Social-Engineering'
	os.system("apt update && apt upgrade")
	os.system("apt install python2 perl")
	os.system("git clone https://github.com/LOoLzeC/social-engineering")
	os.system("mv social-engineering ~")
	print '###### Social-Engineering Berhasil Di Install'
	backtomenu_option()

def spiderbot():
	print '\n###### Menginstall SpiderBot'
	os.system("apt update && apt upgrade")
	os.system("apt install git php")
	os.system("git clone https://github.com/Cvar1984/SpiderBot")
	os.system("mv SpiderBot ~")
	print '###### SpiderBot Berhasil Di Install'
	backtomenu_option()

def ngrok():
	print '\n###### Menginstall Ngrok'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/themastersunil/ngrok')
	os.system('mv ngrok ~')
	print '###### Ngrox Berhasil Di Install'
	backtomenu_option()

def sudo():
	print '\n###### Menginstall sudo'
	os.system('apt update && apt upgrade')
	os.system('apt install ncurses-utils git')
	os.system('git clone https://github.com/st42/termux-sudo')
	os.system('mv termux-sudo ~ && cd ~/termux-sudo && chmod 777 *')
	os.system('cat sudo > /data/data/com.termux/files/usr/bin/sudo')
	os.system('chmod 700 /data/data/com.termux/files/usr/bin/sudo')
	print '###### sudo Berhasil Di Install'
	backtomenu_option()

def ubuntu():
	print '\n###### Menginstall Ubuntu'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/Neo-Oli/termux-ubuntu')
	os.system('mv termux-ubuntu ~ && cd ~/termux-ubuntu && bash ubuntu.sh')
	print '###### Ubuntu Berhasil Di Install'
	backtomenu_option()

def fedora():
	print '\n###### Menginstall Fedora'
	os.system('apt update && apt upgrade')
	os.system('apt install wget git')
	os.system('wget https://raw.githubusercontent.com/nmilosev/termux-fedora/master/termux-fedora.sh')
	os.system('mv termux-fedora.sh ~')
	print '###### Fedora Berhasil Di Install'
	backtomenu_option()

def nethunter():
	print '\n###### Menginstall Kali NetHunter'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/Hax4us/Nethunter-In-Termux')
	os.system('mv Nethunter-In-Termux ~')
	print '###### Kali NetHunter Berhasil Di Install'
	backtomenu_option()

def blackbox():
	print '\n###### Menginstall BlackBox'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git && python2 -m pip install optparse passlib')
	os.system('git clone https://github.com/jothatron/blackbox')
	os.system('mv blackbox ~')
	print '###### BlackBox Berhasil Di Install'
	backtomenu_option()

def xattacker():
	print '\n###### Menginstall XAttacker'
	os.system('apt update && apt upgrade')
	os.system('apt install git perl')
	os.system('cpnm install HTTP::Request')
	os.system('cpnm install LWP::Useragent')
	os.system('git clone https://github.com/Moham3dRiahi/XAttacker')
	os.system('mv XAttacker ~')
	print '###### XAttacker Berhasil Di Install'
	backtomenu_option()

def vcrt():
	print '\n###### Menginstall VCRT'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/LOoLzeC/Evil-create-framework')
	os.system('mv Evil-create-framework ~')
	print '###### VCRT Berhasil Di Install'
	backtomenu_option()

def socfish():
	print '\n###### Menginstall SocialFish'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git && python2 -m pip install wget')
	os.system('git clone https://github.com/UndeadSec/SocialFish')
	os.system('mv SocialFish ~')
	print '###### SocialFish Berhasil Di Install'
	backtomenu_option()

def ecode():
	print '\n###### Menginstall ECode'
	os.system('apt update && apt upgrade')
	os.system('apt install php git')
	os.system('git clone https://github.com/Cvar1984/Ecode')
	os.system('mv Ecode ~')
	print '###### ECode Berhasil Di Install'
	backtomenu_option()

def hashzer():
	print '\n###### Menginstall Hashzer'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/Anb3rSecID/Hashzer')
	os.system('mv Hashzer ~')
	print '###### Hashzer Berhasil Di Install'
	backtomenu_option()

def xsstrike():
	print '\n###### Menginstall XSStrike'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install fuzzywuzzy prettytable mechanize HTMLParser')
	os.system('git clone https://github.com/UltimateHackers/XSStrike')
	os.system('mv XSStrike ~')
	print '###### XSStrike Berhasil Di Install'
	backtomenu_option()

def breacher():
	print '\n###### Menginstall Breacher'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install requests argparse')
	os.system('git clone https://github.com/UltimateHackers/Breacher')
	os.system('mv Breacher ~')
	print '###### Breacher Berhasil Di Install'
	backtomenu_option()

def stylemux():
	print '\n###### Menginstall Termux-Styling'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/BagazMukti/Termux-Styling-Shell-Script')
	os.system('mv Termux-Styling-Shell-Script ~')
	print '###### Termux-Styling Berhasil Di Install'
	backtomenu_option()

def txtool():
	print '\n###### Menginstall TXTool'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 nmap php curl')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/kuburan/txtool')
	os.system('mv txtool ~')
	print '###### TXTool Berhasil Di Install'
	backtomenu_option()

def passgencvar():
	print '\n###### Menginstall PassGen'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone https://github.com/Cvar1984/PassGen')
	os.system('mv PassGen ~')
	print '###### PassGen Berhasil Di Install'
	backtomenu_option()

def owscan():
	print '\n###### Menginstall OWScan'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone https://github.com/Gameye98/OWScan')
	os.system('mv OWScan ~')
	print '###### OWScan Berhasil Di Install'
	backtomenu_option()

def sanlen():
	print '\n###### Menginstall santet-online'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install requests')
	os.system('git clone https://github.com/Gameye98/santet-online')
	os.system('mv santet-online ~')
	print '###### santet-online Berhasil Di Install'
	backtomenu_option()

def spazsms():
	print '\n###### Menginstall SpazSMS'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install requests')
	os.system('git clone https://github.com/Gameye98/SpazSMS')
	os.system('mv SpazSMS ~')
	print '###### SpazSMS Berhasil Di Install'
	backtomenu_option()

def hasher():
	print '\n###### Menginstall Hasher'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install passlib binascii progressbar')
	os.system('git clone https://github.com/ciku370/hasher')
	os.system('mv hasher ~')
	print '###### Hasher Berhasil Di Install'
	backtomenu_option()

def hashgenerator():
	print '\n###### Menginstall Hash-Generator'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install passlib progressbar')
	os.system('git clone https://github.com/ciku370/hash-generator')
	os.system('mv hash-generator ~')
	print '###### Hash-Generator Berhasil Di Install'
	backtomenu_option()

def kodork():
	print '\n###### Menginstall ko-dork'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install urllib2')
	os.system('git clone https://github.com/ciku370/ko-dork')
	os.system('mv ko-dork ~')
	print '###### ko-dork Berhasil Di Install'
	backtomenu_option()

def snitch():
	print '\n###### Menginstall snitch'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/Smaash/snitch')
	os.system('mv snitch ~')
	print '###### snitch Berhasil Di Install'
	backtomenu_option()

def osif():
	print '\n###### Menginstall OSIF'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/ciku370/OSIF')
	os.system('mv OSIF ~')
	print '###### OSIF Berhasil Di Install'
	backtomenu_option()

def nk26():
	print '\n###### Menginstall nk26'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone ')
	os.system('mv nk26 ~')
	print '###### nk26 Berhasil Di Install'
	backtomenu_option()

def devploit():
	print '\n###### Menginstall Devploit'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git && python2 -m pip install urllib2')
	os.system('git clone https://github.com/joker25000/Devploit')
	os.system('mv Devploit ~')
	print '###### Devploit Berhasil Di Install'
	backtomenu_option()

def hasherdotid():
	print '\n###### Menginstall Hasherdotid'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 git')
	os.system('git clone https://github.com/galauerscrew/hasherdotid')
	os.system('mv hasherdotid ~')
	print '###### Hasherdotid Berhasil Di Install'
	backtomenu_option()

def namechk():
	print '\n###### Menginstall Namechk'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/HA71/Namechk')
	os.system('mv Namechk ~')
	print '###### Namechk Berhasil Di Install'
	backtomenu_option()

def xlPy():
	print '\n###### Menginstall xl-py'
	os.system('apt update && apt upgrade')
	os.system('apt install python git')
	os.system('git clone https://github.com/albertoanggi/xl-py')
	os.system('mv xl-py ~')
	print '###### x1-py Berhasil Di Install'
	backtomenu_option()

def beanshell():
	print '\n###### Menginstall Beanshell'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://github.com/amsitlab/amsitlab.github.io/raw/master/dists/termux/amsitlab/binary-all/beanshell_2.04_all.deb')
	os.system('dpkg -i beanshell_2.04_all.deb')
	os.system('rm beanshell_2.04_all.deb')
	print '###### Beanshell Berhasil Di Install'
	print "###### Gunakan Command 'bsh' Untuk Masuk Tools."
	backtomenu_option()

def msfpg():
	print '\n###### Menginstall MSF-Pg'
	os.system('apt update && apt upgrade')
	os.system('apt install git')
	os.system('git clone https://github.com/haxzsadik/MSF-Pg')
	os.system('mv MSF-Pg ~')
	print "###### MSF-Pg Berhasil Di Install"
	backtomenu_option()

def crunch():
	print '\n###### Menginstall Crunch'
	os.system('apt update && apt upgrade')
	os.system('apt install unstable-repo')
	os.system('apt install crunch')
	print "###### Crunch Berhasil Di Install"
	print "###### Gunakan Command 'crunch' Untuk Masuk Tools."
	backtomenu_option()

def webconn():
	print '\n###### Menginstall WebConn'
	os.system('apt update && apt upgrade')
	os.system('apt install python git')
	os.system('git clone https://github.com/SkyKnight-Team/WebConn')
	os.system('mv WebConn ~')
	print "###### WebConn Berhasil Di Install"
	backtomenu_option()

def binploit():
	print '\n###### Menginstall Binary Exploitation'
	os.system('apt update && apt upgrade')
	os.system('apt install gdb radare2 ired ddrescue bin-utils yasm strace ltrace cdb hexcurse memcached llvmdb')
	print "###### Binary Exploitation Berhasil Di Install"
	print "###### Tutorial: https://youtu.be/3NTXFUxcKPc"
	backtomenu_option()

def textr():
	print '\n###### Menginstall Textr'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://raw.githubusercontent.com/amsitlab/textr/master/textr_1.0_all.deb')
	os.system('dpkg -i textr_1.0_all.deb')
	os.system('rm textr_1.0_all.deb')
	print '###### Textr Berhasil Di Install'
	print "###### Gunakan Command 'textr' Untuk Masuk Tools."
	backtomenu_option()

def apsca():
	print '\n###### Menginstall ApSca'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://raw.githubusercontent.com/BlackHoleSecurity/apsca/master/apsca_0.1_all.deb')
	os.system('dpkg -i apsca_0.1_all.deb')
	os.system('rm apsca_0.1_all.deb')
	print '###### ApSca Berhasil Di Install'
	print "###### Gunakan Command 'apsca' Untuk Masuk Tools."
	backtomenu_option()

def amox():
	print '\n###### Menginstall amox'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://gitlab.com/dtlily/amox/raw/master/amox_1.0_all.deb')
	os.system('dpkg -i amox_1.0_all.deb')
	os.system('rm amox_1.0_all.deb')
	print '###### Done'
	print "###### Gunakan Command 'amox' Untuk Masuk Tools."
	backtomenu_option()

def fade():
	print '\n###### Menginstall FaDe'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install requests')
	os.system('git clone https://github.com/Gameye98/FaDe')
	os.system('mv FaDe ~')
	print '###### FaDe Berhasil Di Install'
	backtomenu_option()

def ginf():
	print '\n###### Menginstall GINF'
	os.system('apt update && apt upgrade')
	os.system('apt install git php')
	os.system('git clone https://github.com/Gameye98/GINF')
	os.system('mv GINF ~')
	print '###### GINF Berhasil Di Install'
	backtomenu_option()

def auxile():
	print '\n###### Menginstall AUXILE'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install requests bs4 pexpect')
	os.system('git clone https://github.com/CiKu370/AUXILE')
	os.system('mv AUXILE ~')
	print '###### AUXILE Berhasil Di Install'
	backtomenu_option()

def inther():
	print '\n###### Menginstall inther'
	os.system('apt update && apt upgrade')
	os.system('apt install git ruby')
	os.system('git clone https://github.com/Gameye98/inther')
	os.system('mv inther ~')
	print '###### inther Berhasil Di Install'
	backtomenu_option()

def hpb():
	print '\n###### Menginstall HPB'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://raw.githubusercontent.com/Cvar1984/HPB/master/html_0.1_all.deb')
	os.system('dpkg -i html_0.1_all.deb')
	os.system('rm html_0.1_all.deb')
	print '###### HPB Berhasil Di Install'
	print "###### Gunakan Command 'hpb' Untuk Masuk Tools."
	backtomenu_option()

def fmbrute():
	print '\n###### Menginstall FMBrute'
	os.system('apt update && apt upgrade')
	os.system('apt install git python && python -m pip install requests')
	os.system('git clone https://github.com/BlackHoleSecurity/FMBrute')
	os.system('mv FMBrute ~')
	print '###### FMBrute Berhasil Di Install'
	backtomenu_option()

def hashid():
	print '\n###### Menginstall HashID'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 && python2 -m pip install hashid')
	print "###### HashID"
	print "###### Gunakan Command 'hashid -h' Untuk Melihat HashID"
	backtomenu_option()

def gpstr():
	print '\n###### Menginstall GPS Tracking'
	os.system('apt update && apt upgrade')
	os.system('apt install php git')
	os.system('git clone https://github.com/indosecid/gps_tracking')
	os.system('mv gps_tracking ~')
	print "###### GPS Tracking Berhasil Di Install"
	backtomenu_option()

def pret():
	print '\n###### Menginstall PRET'
	os.system('apt update && apt upgrade')
	os.system('apt install python2 imagemagick git')
	os.system('python2 -m pip install colorama pysnmp')
	os.system('git clone https://github.com/RUB-NDS/PRET')
	os.system('mv PRET ~')
	print "###### PRET Berhasil Di Install"
	backtomenu_option()

def autovisitor():
	print '\n###### Menginstall AutoVisitor'
	os.system('apt update && apt upgrade')
	os.system('apt install git curl')
	os.system('git clone https://github.com/wannabeee/AutoVisitor')
	os.system('mv AutoVisitor ~')
	print "###### AutoVisitor Berhasil Di Install"
	backtomenu_option()

def atlas():
	print '\n###### Menginstall Atlas'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2 && python2 -m pip install urllib2')
	os.system('git clone https://github.com/m4ll0k/Atlas')
	os.system('mv Atlas ~')
	print "###### Atlas Berhasil Di Install"
	backtomenu_option()

def hashcat():
	print '\n###### Menginstall Hashcat'
	os.system('apt update && apt upgrade')
	os.system('apt install unstable-repo')
	os.system('apt install hashcat')
	print "###### Hashcat Berhasil Di Install"
	print "###### Gunakan Command 'hashcat' Untuk Masuk Tools."
	backtomenu_option()

def liteotp():
	print '\n###### Menginstall LiteOTP'
	os.system('apt update && apt upgrade')
	os.system('apt install php wget')
	os.system('wget https://raw.githubusercontent.com/Cvar1984/LiteOTP/master/build/main.phar -O $PREFIX/bin/lite')
	print "###### LiteOTP Berhasil Di Install"
	print "###### Gunakan Command 'lite' Untuk Masuk Tools."
	backtomenu_option()

def fbbrutex():
	print '\n###### Menginstall FBBrute'
	os.system('apt update && apt upgrade')
	os.system('apt install git python && python -m pip install requests')
	os.system('git clone https://github.com/Gameye98/FBBrute')
	os.system('mv FBBrute ~')
	print '###### FBBrute Berhasil Di Install'
	backtomenu_option()

def fim():
	print '\n###### Menginstall fim'
	os.system('apt update && apt upgrade')
	os.system('apt install git python && python -m pip install requests bs4')
	os.system('git clone https://github.com/karjok/fim')
	os.system('mv fim ~')
	print '###### fim Berhasil Di Install'
	backtomenu_option()

def rshell():
	print '\n###### Menginstall RShell'
	os.system('apt update && apt upgrade')
	os.system('apt install git python && python -m pip install colorama')
	os.system('git clone https://github.com/Jishu-Epic/RShell')
	os.system('mv RShell ~')
	print '###### RShell Berhasil Di Install'
	backtomenu_option()

def termpyter():
	print '\n###### Menginstall TermPyter'
	os.system('apt update && apt upgrade')
	os.system('apt install git python')
	os.system('git clone https://github.com/Jishu-Epic/TermPyter')
	os.system('mv TermPyter ~')
	print '###### TermPyter Berhasil Di Install'
	backtomenu_option()

def maxsubdofinder():
	print '\n###### Menginstall MaxSubdoFinder'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install requests')
	os.system('git clone https://github.com/maxteroit/MaxSubdoFinder')
	os.system('mv MaxSubdoFinder ~')
	print '###### MaxSubdoFinder Berhasil Di Install'
	backtomenu_option()

def jadx():
	print '\n###### Menginstall jadx'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://github.com/Lexiie/Termux-Jadx/blob/master/jadx-0.6.1_all.deb?raw=true')
	os.system('dpkg -i jadx-0.6.1_all.deb?raw=true')
	os.system('rm -rf jadx-0.6.1_all.deb?raw=true')
	print '###### jadx Berhasil Di Install'
	print "###### Gunakan Command 'jadx' Untuk Masuk Tools."
	backtomenu_option()

def pwnedornot():
	print '\n###### Menginstall pwnedOrNot'
	os.system('apt update && apt upgrade')
	os.system('apt install git python')
	os.system('python -m pip install requests')
	os.system('git clone https://github.com/thewhiteh4t/pwnedOrNot')
	os.system('mv pwnedOrNot ~')
	print '###### pwned0rNot Berhasil Di Install'
	backtomenu_option()

def maclook():
	print '\n###### Menginstall Mac-Lookup'
	os.system('apt update && apt upgrade')
	os.system('apt install git python')
	os.system('python -m pip install requests')
	os.system('git clone https://github.com/T4P4N/Mac-Lookup')
	os.system('mv Mac-Lookup ~')
	print '###### Mac-Lookup Berhasil Di Install'
	backtomenu_option()

def f4k3():
	print '\n###### Menginstall F4K3'
	os.system('apt update && apt upgrade')
	os.system('apt install dpkg wget')
	os.system('wget https://github.com/Gameye98/Gameye98.github.io/blob/master/package/f4k3_1.0_all.deb')
	os.system('dpkg -i f4k3_1.0_all.deb')
	os.system('rm -rf f4k3_1.0_all.deb')
	print '###### F4K3 Berhasil Di Install'
	print "###### Gunakan Command 'f4k3' Untuk Masuk Tools."
	backtomenu_option()

def katak():
	print '\n###### Menginstall Katak'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('python2 -m pip install requests progressbar')
	os.system('git clone https://github.com/Gameye98/Katak')
	os.system('mv Katak ~')
	print '###### Katak Berhasil Di Install'
	backtomenu_option()

def heroku():
	print '\n###### Menginstall heroku'
	os.system('apt update && apt upgrade')
	os.system('apt install nodejs')
	os.system('npm install heroku -g')
	print '###### heroku Berhasil Di Install'
	print "###### Gunakan Command 'heroku' Untuk Masuk Tools."
	backtomenu_option()

def google():
	print '\n###### Menginstall google'
	os.system('apt update && apt upgrade')
	os.system('apt install python')
	os.system('python -m pip install google')
	print '###### google Berhasil Di Install'
	print "###### Gunakan Command 'google' Untuk Masuk Tools."
	backtomenu_option()

def billcypher():
	print '\n###### Menginstall BillCypher'
	os.system('apt update && apt upgrade')
	os.system('apt install git python')
	os.system('python -m pip install argparse dnspython requests urllib3 colorama')
	os.system('git clone https://github.com/GitHackTools/BillCipher')
	os.system('mv BillCypher ~')
	print '###### BillCypher Berhasil Di Install'
	backtomenu_option()

def vbug():
	print '\n###### Menginstall vbug'
	os.system('apt update && apt upgrade')
	os.system('apt install git python2')
	os.system('git clone https://github.com/Gameye98/vbug')
	os.system('mv vbug ~')
	print '###### vbug Berhasil Di Install'
	backtomenu_option()

def termuxfitur():
        print '\n###### Menginstall TermuxFitur'
	os.system('apt update && apt upgrade')
	os.system('apt install git python')
	os.system('git clone https://github.com/Tutorial-Termux-Hacking/TermuxFitur')
	os.system('mv TermuxFitur')
	print '##### TermuxFitur Berhasil Di Install'
	backtomenu_option()

def wifiplugin():
	print '\n###### Menginstall Wifi_Plugin'
        os.system('apt update && apt upgrade')
        os.system('apt install git python2')
	os.system('apt install wget curl')
        os.system('git clone https://github.com/Tutorial-Termux-Hacking/Wifi_Plugin')
        os.system('mv Wifi_Plugin')
        print '##### Wifi_Plugin Berhasil Di Install'
        backtomenu_option()

def tload():
	print '\n###### Menginstall T-LOAD'
        os.system('apt update && apt upgrade')
        os.system('apt install git python')
        os.system('git clone https://github.com/Tutorial-Termux-Hacking/T-LOAD')
        os.system('mv T-LOAD')
        print '##### T-LOAD Berhasil Di Install'
        backtomenu_option()

def fbhack():
	print '\n###### Menginstall FBhacking'
        os.system('apt update && apt upgrade')
        os.system('apt install git python')
	os.system('apt install git')
	os.system('pip install colorama')
        os.system('git clone https://github.com/Tutorial-Termux-Hacking/FBhacking')
        os.system('mv FBhacking')
        print '##### FBhacking Berhasil Di Install'
        backtomenu_option()

def thextools():
	print '\n###### Menginstall TheXTools'
	os.system('apt update && apt upgrade')
	os.system('apt install python2')
	os.system('pip2 install requests')
	os.system('apt install git')
	os.system('git clone https://github.com/Tutorial-Termux-Hacking/TheXTools')
	os.system('mv TheXTools')
	print '##### TheXTools Berhasil Di Install'
	backtomenu_option()
