import sys
import random as rand

from scapy.layers.inet import IP, Ether, TCP, ICMP, fragment
from scapy.sendrecv import send, sendp, sniff
from scapy import *

incoming = sniff(filter='TCP and IP') #sniffs packets with TCP and IP layers
incoming.nsummary() #returns a list of the sniffed fragments 
i0 = incoming[0] #frag0
i1 = incoming[1] #frag1
i2 = incoming[2] #frag2
i3 = incoming[3] #TCP ack?

#or

fragmentsInput = [fragment for fragment in incoming] #if n fragments instead of 3 fragments, store in a list


def detection1(fragments): #pass fragmentsInput in line 17 to it 

    for fragment in fragments: #need to know how to access fragment object to see Fragment Offset and Fragment Protocol and Transport Length
        if fragment[IP].frag == 0 and fragment.haslayer(TCP) and len(fragment[IP]) < 8:  #Tmin here is 8 by default(we should make sure which Tmin to choose)
            print("Overlapping attack possibility, drop packet!") #prints the error
            return
        elif fragment.frag == 0 and fragment.proto == 'tcp': # could include this in line 21 as an OR statement later on
            print("Overlapping attack possibility, drop packet!")
            return
        else:
            print("All is good...") #or do nothing, no attack detected 
            return 


def detection2(fragments): #check if syn field is different in different fragments (to bypass a firewall for example) (if a syn was sent in the first header, then modified in the second fragment)
    for i in range(0, len(fragments) - 1): #fragments input is a list of the fragments detected by sniff 
        if fragments[i][IP].syn != fragments[i+1][IP].syn: #compare 2 consecutive fragments, if syn is in both and different, then there is an attack
            print("Possibility of an attack, drop packet")
            return
    
    return


def detection3(fragments): #against TearDrop attack
    for i in range(0, len(fragments) - 1): #fragments input is a list of the fragments detected by sniff 

        #checks 2 consecutive fragments
        #if 1st fragment has offset 0, and has MF flag on
        #and second packet has MF flag off (in this case just check flag if = or not to MF)
        #and offset of second packet + payload size is LESS than payload size of first fragment
        #return the detection

        if ((fragments[i][IP].frag == 0) and (fragments[1][IP].flags=="MF") and (fragments[i+1][IP].flags!="MF") and (fragments[i+1][IP].frag + len(fragments[i+1][IP])  < len(fragments[i][IP]))): 
            print("Possibility of an attack, drop packet")
            return
    
    return




                     

