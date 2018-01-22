# PCAP_WIRESHARK_JSON_PCAP_C++
Attached Files:
File http.pcap (25.198 KB)
File tftp_rrq.pcap (30.726 KB)
File http.output (5.182 KB)
File tftp_rrq.output (11.65 KB)
Write a program that reads a PCAP file and provides output about that file.

1. Program will be called from the command line using the source file name as the first command line parameter:

 test> pcap_decode1 <filename>

2. Program will read the pcap file, parsing the main file header, and each packet header. See https://wiki.wireshark.org/Development/LibpcapFileFormat for a discussion of the PCAP file format.

 <HINT>  the first example I am giving you (http.pcap) is written by a process using little-endian format for the headers.  

3. Program will write out a JSON  format file. Including the following fields (indexed with the specified strings)

"magicNumber" -- PCAP magic number
"majorVersion"   -- PCAP file major version number
"minorVersion" -- PCAP minor version number
"thisZone" -- PCAP time zone (GMT to local correction)
"sigFigs" -- accuracy of timestamps
"snapLen" -- maximum packet size
"network" -- data link type
"count" -- total number of packets read in this file. Your program will have to calculate this
and for each packet

 a packet number, starting at 0 (See posted format)
"tmSec" -- timestamp seconds
"tmUSec" -- timestamp microseconds
"inclLen" -- number of octets/bytes of packet in the pcap file
"origLen" -- number of octets/byets of packet on the network (will be same as inclLen unless bigger than snapLen

Sample output format: (newlines don't matter here. Also, order of fields in {...}  don't matter. 


{“snaplen”: 65535, ”magicNumber”: 2712847316, ”minorVersion”: 4, ”sigFigs”: 0, “network”: 1, ”majorVersion”: 2, ”thiszone”: 0, "count": 43,
 {"0": {“tsSec”: 1084443427, “incLen”: 62, “tsUSec”: 311224, “origLen”: 62},

  "1": {“tsSec”: 1084443428, “incLen”: 62, “tsUSec“: 222534, “origLen”: 62},

  "2": {“tsSec”: 1084443428, “incLen”: 54, “tsUSec”: 222534, “origLen”: 54},

  "3": {“tsSec”: 1084443428, “incLen”: 533, “tsUSec”: 222534, “origLen”: 533},

  "4": {“tsSec”: 1084443428, “incLen”: 54, “tsUSec”: 783340, “origLen“: 54},

  "5": {“tsSec”: 1084443428, “incLen”: 1434, “tsUSec”: 993643, “origLen”: 1434}, ...

}}
