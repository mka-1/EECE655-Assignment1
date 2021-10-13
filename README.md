### Dependencies 
Please make sure to Install Scapy beforehand in a virtual environment using the following command: $ pip install --pre scapy[basic] <br />
### Main tools
-The **main** attack is in **synflood1.py** and **synfloodspoofed.py** <br />
-The **main** detection code is in **detectsynflood1.py** <br />
### Extra Tools 
-All other .py files are **extra** overlappng fragments attacks, there is also the extradetection.py code written for those overlapping fragments but it is not fully functional so it can be considered as a pseudo code <br /> <br />
### Running the files
-To run the attack files please use the following command <br /> 
  *python filename.py py preferreddestip preferrednbofpackets* <br /> 
Example: python synflood1.py 123.123.123.123 45 
