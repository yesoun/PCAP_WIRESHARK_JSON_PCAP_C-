/**

Author: Yassine Maalej                  Email: maalej.yessine@gmail.com || maal4948@vandals.uidaho.edu
Class: Network Security CS 538
Assignment1: Write a program that reads a PCAP file and provides output about that file.
The pcapfile format is as in :  https://wiki.wireshark.org/Development/LibpcapFileFormat

The Expected Output Will Look Like This:
first part of the main file header details:
{
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------
"magicNumber" -- PCAP magic number
"majorVersion"   -- PCAP file major version number
"minorVersion" -- PCAP minor version number
"thisZone" -- PCAP time zone (GMT to local correction)
"sigFigs" -- accuracy of timestamps
"snapLen" -- maximum packet size
"network" -- data link type
"count" -- total number of packets read in this file. Your program will have to calculate this
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------

and then for each packet we give its details with brackets
--------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------
 a packet number, starting at 0 (See posted format)
"tmSec" -- timestamp seconds
"tmUSec" -- timestamp microseconds
"inclLen" -- number of octets/bytes of packet in the pcap file
"origLen" -- number of octets/byets of packet on the network (will be same as inclLen unless bigger than snapLen
--------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------

*/

#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/types.h>
#include <stdlib.h>

typedef __u32  guint32;
typedef __u16  guint16;
typedef   int   gint32;


using namespace std;

/**This header starts the libpcap file and will be followed by the first packet header:*/
typedef struct pcap_hdr_s {
	guint32 magic_number;   /* magic number */
	guint16 version_major;  /* major version number */
	guint16 version_minor;  /* minor version number */
	gint32  thiszone;       /* GMT to local correction */
	guint32 sigfigs;        /* accuracy of timestamps */
	guint32 snaplen;        /* max length of captured packets, in octets */
	guint32 network;        /* data link type */
} pcap_hdr_t;

/** Each captured packet starts with (any byte alignment possible): */
typedef struct pcaprec_hdr_s {
	guint32 ts_sec;         /* timestamp seconds */
	guint32 ts_usec;        /* timestamp microseconds */
	guint32 incl_len;       /* number of octets of packet saved in file */
	guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int main(int argc, char const* argv[])
{
    // if no pcap file is given after the executable main_pcap_json.o then return 1
	if (argc != 2) {
		printf("NO PCAP FILE IS GIVEN AFTER ./main_pcap_json.o ", argv[0]);
		return 1;
	}

    // else we open the PCAP file in read only mode since in this assignemnet we do not have to write anything.
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		cout<<"ERROR OPENING FILE"<< endl;
        return 1;
	}

	int pcap_hdr_l = sizeof(pcap_hdr_t);
	pcap_hdr_t *pcap_header = (pcap_hdr_t *)malloc(pcap_hdr_l);
	int hdr_l = read(fd, pcap_header, pcap_hdr_l);

	int pcap_pkthdr_l = sizeof(pcaprec_hdr_t);
	pcaprec_hdr_t *pcap_pktheader = (pcaprec_hdr_t *)malloc(pcap_pkthdr_l);

    // total number of packets
    int countPackets=0;
    // first bracket
    cout<< "{" << endl;
    //going throught the packet headers
    while (true){
        int pkthdr_l = read(fd, pcap_pktheader, pcap_pkthdr_l);
        void *pkt = malloc(pcap_pktheader->incl_len);
        int pkt_l = read(fd, pkt, pcap_pktheader->incl_len);
        if (pkt_l != pcap_pktheader->incl_len) {
            break;
        }
        countPackets +=1;
        printf("\"%d\": \{",countPackets);
        printf("\"tsSec\": %d, ", pcap_pktheader->ts_sec);
        printf("\"incLen\": %d, ", pcap_pktheader->incl_len);
        printf("\"tsUSec\": %d, ", pcap_pktheader->ts_usec);
        printf("\"origLen\": %d \}, ", pcap_pktheader->orig_len);
        cout << endl;
    }

    // the total number of packets
    int totalNumberPackets=countPackets;

	/** beginninjg of typing of the main file header*/
	printf("\"snaplen\": %d, ", pcap_header->snaplen);
	printf("\"magicNumber\": %d, ",      (pcap_header->magic_number));
	printf("\"minorVersion\": %d, ",      pcap_header->version_minor);
	printf("\"sigFigs\": %d, ",      pcap_header->version_minor);
	printf("\"network\": %d, ",      pcap_header->network);
	printf("\"majorVersion\": %d, ",      pcap_header->version_major);
	printf("\"thiszone\": %d, ",      pcap_header->thiszone);
    printf("\"count\": %d, ",      totalNumberPackets);

    // ending bracket
    cout<< "}}"<<endl;


	close(fd);

	return 0;
}
