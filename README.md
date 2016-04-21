
### License
  Copyright(c) 2016 Viosoft Corporation.
  All rights reserved.

  This program is free software; you can redistribute it and/or modify it  
  under the terms and conditions of the GNU General Public License,  
  version 2, as published by the Free Software Foundation.  

  This program is distributed in the hope that it will be useful, but WITHOUT  
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or  
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for  
  more details.  

  You should have received a copy of the GNU General Public License along with  
  this program; if not, write to the Free Software Foundation, Inc.,  
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.  
  
  
### Overview
Generate .pcap files from predefined .cfg file to help with IMIX testing  
in PROX/DATS.

### Prerequisites
gcc
make

### How to run
##### Compile
make  
  
  
##### List available template packets
./PcapGenerator -l


##### Generate Output.pcap from example.cfg
./PcapGenerator -f example.cfg -o Output.pcap
