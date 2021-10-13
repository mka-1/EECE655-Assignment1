from scapy.all import *
#the code was written by Mohamad, Chloe and Dina
#from scapy.layers.inet import IP,TCP
#detecting synflood from a source IP address
#to detect a synflood attack we can check if a number of TCP packets with syn set to 1 are generated from the same ip source within a specified time interval
#first filter the sniffed packets recieved to the ones that contain a TCP layer with the TCP syn flag set to one, and show a summary of those packets
packets = sniff(filter='tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) == tcp-syn', count=100, prn=lambda x:x.summary())#https://stackoverflow.com/questions/38803392/scapy-sniff-filter-tcp-with-syn-ack , https://stackoverflow.com/questions/53803068/scapy-multiple-sniff-filters-not-working
currenttime=datetime.now() #the time of starting the packet sniff
captureddata={} #create a dictionary to keep hold of the number of packets sents with syn=1 associated with each source ip
time={} #create a dictionary to keep hold of the time from the first packet an ip source generates, this will then be used to find the time interval by which a certain number of packets are sent to set a threshold
currenttime=datetime.now()
c=0#initialize c
for packet in packets:
    c+=1#counter for the spoofedip part to check if a large amount of such traffic is generated within a short interval of time
    srcip=packet[IP].src
    if srcip in captureddata:
        captureddata[srcip] +=1 #if source is already in the dictionary, increment the number of TCP packets with syn==1 sent from this source
        #the numbers 20 for packets and 4 for seconds were chosen based on testing different numbers
        if (captureddata[srcip]>20) and (datetime.now() - time[srcip]).total_seconds() < 4: #to get the syntax of this "total_seconds() and time interval we asked a previous 655 student about it"
            print("A possible syn flood attack is detected from:"+ srcip)
            #reset
            time={}
            captureddata= {}
            

    else:
        captureddata[srcip] = 1 #first TCP packet with syn==1 seen from this ip source
        time[srcip] = datetime.now() #record the time when the first TCP packet with a syn flag set is recieved from this source ip

#for spoofed ips, detect a large amount of traffic from different sources in a short amount of time
if (c>35) and (datetime.now() - currenttime).total_seconds() < 2:
    print("detected a possible attack from spoofed ips")
    currenttime=datetime.now()#reset
    c=0 #reset counter
