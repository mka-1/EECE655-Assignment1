### Dependencies 
Please make sure to Install Scapy beforehand in a virtual environment using the following command: <br /> 
$ pip install --pre scapy[basic] <br />
### Main tools
-The **main** attack is in **synflood1.py** and **synfloodspoofed.py** <br />
-The **main** detection code is in **detectsynflood1.py** <br /> 
-Note: When running the detection code, a certain number of sniff counts was set. So if the chosen packet nb is significantly less than that, run the detection file on a terminal then run the attack on another terminal. After the attack is executed, go to the detection terminal and press Cntrl C to break the code and stop the sniff process. Once the code breaks/ends you will be able to see the print statement showing that an attack is detected. 
### Extra Tools 
-All other .py files are **extra** overlapipng fragments attacks, there is also the extradetection.py code written for those overlapping fragments but it is not fully functional so it can be considered as a pseudo code <br /> 
-fromslides.py is an overlapping fragments attack of the port number, it is an implementation of the attack in the lecture slides <br />
-udplayer.py is also an overlapping fragment attack, but it is implemented on a UDP layer <br />
-extra-moodleRFC.py is also an overlapping fragment attack on the TCP syn flag, the attack concept is mentioned in example 4.1 in the RFC 1858 folder on moodle 
### Running the files
-To run the attack files please use the following command <br /> 
  *python filename.py py preferreddestip preferrednbofpackets* <br /> 
Example: python synflood1.py 123.123.123.123 45 
