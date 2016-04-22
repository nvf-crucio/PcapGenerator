
/*
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
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include "PcapGenerator.h"
#include "TemplatePackets.inc"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

PacketTemplate PacketTemplatesList[] = {
    {
        .Name = "udp",
        .PacketSize = sizeof(template_udp_packet),
        .PacketBuffer = template_udp_packet
    },
    
    {
        .Name = "tcp-syn",
        .PacketSize = sizeof(template_tcp_packet),
        .PacketBuffer = template_tcp_packet
    },
    
    {
        .Name = "arp",
        .PacketSize = sizeof(template_arp_packet),
        .PacketBuffer = template_arp_packet
    }
};

unsigned int CurrentLine = 0; // Current Line Being Processed

bool initialize_pcap_file(FILE *pcap)
{
    struct pcap_hdr header;
    header.magic_number = 0xa1b2c3d4;
    header.version_major = 0x02;
    header.version_minor = 0x04;
    header.thiszone = 0x00;
    header.sigfigs = 0x00;
    header.snaplen = 0x40000;
    header.network = 0x01;
    return (fwrite(&header, sizeof(char), sizeof(header), pcap) == sizeof(header));
}

bool write_packet(struct ether_addr *DstMac, uint32_t DstIPv4,
                  struct ether_addr *SrcMac, uint32_t SrcIPv4,
                  unsigned char Packet[], size_t Length,
                  unsigned int Flags,
                  FILE *pcap)
{
    unsigned char pkt_buf[Length];
    memcpy(pkt_buf, Packet, Length);
    struct ether_hdr *ether_header = (struct ether_hdr *) pkt_buf;
    struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *) (&pkt_buf[sizeof(struct ether_hdr)]);
    
    if ((Flags & MODIFY_SOURCE_IPV4) == MODIFY_SOURCE_IPV4)
        ipv4_header->src_addr = SrcIPv4;
    
    if ((Flags & MODIFY_DESTINATION_IPV4) == MODIFY_DESTINATION_IPV4)
        ipv4_header->dst_addr = DstIPv4;
    
    if ((Flags & MODIFY_SOURCE_MAC) == MODIFY_SOURCE_MAC)
        memcpy(&ether_header->_s_addr.addr_bytes, &SrcMac->addr_bytes, ETHER_ADDR_LEN);
    
    if ((Flags & MODIFY_DESTINATION_MAC) == MODIFY_DESTINATION_MAC)
        memcpy(&ether_header->_d_addr.addr_bytes, &DstMac->addr_bytes, ETHER_ADDR_LEN);
    
    struct pcaprec_hdr rec_header;
    rec_header.ts_sec = 0x00;
    rec_header.ts_usec = 0x00;
    rec_header.incl_len = Length;
    rec_header.orig_len = Length;
    
    return (fwrite(&rec_header, sizeof(char), sizeof(rec_header), pcap) == sizeof(rec_header) &&
            fwrite(pkt_buf, sizeof(char), Length, pcap) == Length);
}

bool string_to_mac_addr(char *Input, struct ether_addr *MAC)
{
    unsigned int MACArr[ETHER_ADDR_LEN];
    
    if (sscanf(Input, "%x:%x:%x:%x:%x:%x", &MACArr[0], &MACArr[1], &MACArr[2], &MACArr[3], &MACArr[4], &MACArr[5]) != ETHER_ADDR_LEN)
        return false;
    
    unsigned int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (MACArr[i] > 0xFF) return false;
        MAC->addr_bytes[i] = (unsigned char) MACArr[i];
    }
    
    return true;
}

// Remove Unnecessary Spaces/NL/CR
void trim_line(char Input[])
{
    // Trim Left
    int i, j = 0, InputLength = strlen(Input);
    for (i = 0; i < InputLength; i++)
    {
        if (Input[i] == ' ') j = i + 1;
        else break;
    }
    
    for (i = 0; j < InputLength; j++, i++)
    {
        Input[i] = Input[j];
    }
    
    Input[i] = '\0';
    
    // Trim Right
    InputLength = strlen(Input);
    for (i = InputLength - 1; i >= 0; i--)
    {
        if (Input[i] == ' ' || Input[i] == '\n' || Input[i] == '\r')
            Input[i] = '\0';
        else break;
    }
    return;
}

bool skip_to_next_section(FILE *ConfigInput, char Line[], size_t Size)
{
    do
    {
        trim_line(Line);
        if (Line[0] == '\0' || Line[0] == ';')
        {
            CurrentLine++;
            continue; // Empty Line
        }
        
        if (Line[0] == '[') return true;
        CurrentLine++;
    } while (fgets(Line, Size, ConfigInput));
    
    return true;
}

void print_help()
{
    const char *Help = "\n"\
    "Pcap Generator "VERSION"\n"\
    " -o\tOutput Pcap File\n"\
    " -f\tInput Configuration File\n"\
    " -l\tPrint a List of available packet templates\n"\
    " -h\tPrint this help\n";
    
    puts(Help);
    return;
}

void print_available_packet_templates()
{
    printf("Name\t\tSize\n");
    printf("=========================================\n");
    
    size_t i;
    for (i = 0; i < sizeof(PacketTemplatesList) / sizeof(PacketTemplate); i++)
    {
        printf("%s\t\t%u Bytes\n", PacketTemplatesList[i].Name, PacketTemplatesList[i].PacketSize);
    }
    printf("\n");
    return;
}

int main(int argc, char *argv[])
{
    char ConfigFilePath[PATH_MAX] = { 0 }, OutputFilePath[PATH_MAX] = { 0 };
    opterr = 0;
    int c;
    while ((c = getopt(argc, argv, "hlf:o:")) != -1)
    {
        switch (c)
        {
            case 'f':
                strncpy(ConfigFilePath, optarg, strlen(optarg));
                break;
                
            case 'o':
                strncpy(OutputFilePath, optarg, strlen(optarg));
                break;
                
            case 'h':
                print_help();
                return 0;
                
            case 'l':
                print_available_packet_templates();
                return 0;
                
            case '?':
                if (optopt == 'f')
                    fprintf (stderr, "Option -%c requires a file name.\n", optopt);
                else if (optopt == 'o')
                    fprintf(stderr, "Option -%c requires a file name.\n", optopt);
                else if (isprint(optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return -1;
                
            default:
                return -1;
        }
    }
    
    if (ConfigFilePath[0] == '\0')
    {
        printf("\nError: No Configuration File Specified!\n");
        print_help();
        return -1;
    }
    
    if (OutputFilePath[0] == '\0')
    {
        printf("\nError: No Output File Path Specified!\n");
        print_help();
        return -1;
    }
    
    FILE *PcapOutput = fopen(OutputFilePath, "wb");
    if (PcapOutput == NULL)
    {
        printf("Error: Unable to Create Output Pcap File '%s' !\n", OutputFilePath);
        return -1;
    }
    
    FILE *ConfigInput = fopen(ConfigFilePath, "rb");
    if (ConfigInput == NULL)
    {
        printf("Error: Unable to Open Configuration File '%s' !\n", ConfigFilePath);
        return -1;
    }
    
    if (initialize_pcap_file(PcapOutput) == false)
    {
        printf("Error: Unable to Initialize Output Pcap File !\n");
        return -1;
    }
    
    struct ether_addr DstMac[MAX_ADDRESS_COUNT];
    struct ether_addr SrcMac[MAX_ADDRESS_COUNT];
    uint32_t SrcIPv4[MAX_ADDRESS_COUNT];
    uint32_t DstIPv4[MAX_ADDRESS_COUNT];
    
    size_t SrcMacCount, DstMacCount, SrcIPv4Count, DstIPv4Count;
    
    unsigned char PacketBuffer[MAXIMUM_PACKET_SIZE];
    unsigned long int Rep, PacketWritten = 0;
    unsigned int Flags;
    char Input[MAX_INPUT_LINE], Name[128], Value[MAX_INPUT_LINE], Address[MAX_ADDRESS];
    
    char *AddressBuffer, *CurrentAddress; // Temporary Pointers
    
    size_t i, j;
    
    int PacketBufferLength;
    memset(Input, '\0', sizeof(Input));
    
    while (feof(ConfigInput) == false)
    {
        // Reset defaults
        Rep = 1;
        Flags = 0;
        PacketBufferLength = 0;
        SrcMacCount = 0;
        DstMacCount = 0;
        SrcIPv4Count = 0;
        DstIPv4Count = 0;
        
        if (skip_to_next_section(ConfigInput, Input, sizeof(Input)) == false)
            break;
        
        while (fgets(Input, sizeof(Input), ConfigInput))
        {
            CurrentLine++;
            trim_line(Input);
            if (Input[0] == '\0' || Input[0] == ';') continue; // Empty Line
            if (Input[0] == '[') break;
            
            char *Line = Input; // Temporary Pointer to Line
            char *EntryName = strsep(&Line, "=");
            char *EntryValue = strsep(&Line, "=");
            
            if (EntryName == NULL || EntryValue == NULL) continue;
            
            strncpy(Name, EntryName, strlen(EntryName));
            strncpy(Value, EntryValue, strlen(EntryValue));
            
            Name[strlen(EntryName)] = '\0';
            Value[strlen(EntryValue)] = '\0';
            
            trim_line(Name);
            trim_line(Value);
            
            if (strcmp(Name, "pkt buf") == 0)
            {
                // Check if it's in templates
                for (i = 0; i < sizeof(PacketTemplatesList) / sizeof(PacketTemplate); i++)
                {
                    if (strcmp(PacketTemplatesList[i].Name, Value) == 0)
                    {
                        memcpy(PacketBuffer, PacketTemplatesList[i].PacketBuffer, PacketTemplatesList[i].PacketSize);
                        PacketBufferLength = PacketTemplatesList[i].PacketSize;
                        break;
                    }
                }
                
                if (PacketBufferLength == 0) // Not From Templates, Parse 'pkt buf'
                {
                    char *CurrentByte, *Buffer = Value;
                    while ((CurrentByte = strsep(&Buffer, " ")) != NULL)
                    {
                        int binary_byte = strtol(CurrentByte, NULL, 16);
                        if (binary_byte > 255 || binary_byte < 0)
                        {
                            printf("Line %d: Packet Parsing Error !\n", CurrentLine);
                            return -1;
                        }
                        PacketBuffer[PacketBufferLength++] = (unsigned char) binary_byte;
                    }
                }
            }
            else if (strcmp(Name, "src ipv4") == 0)
            {
                AddressBuffer = Value;
                while ((CurrentAddress = strsep(&AddressBuffer, ",")) != NULL &&
                       (SrcIPv4Count < MAX_ADDRESS_COUNT))
                {
                    strncpy(Address, CurrentAddress, strlen(CurrentAddress));
                    Address[strlen(CurrentAddress)] = '\0';
                    trim_line(Address);
                    
                    SrcIPv4[SrcIPv4Count] = inet_addr(Address);
                    if (SrcIPv4[SrcIPv4Count] == (in_addr_t)(-1))
                    {
                        printf("Line %d: Source IPv4 Error !\n", CurrentLine);
                        return -1;
                    }
                    Flags |= MODIFY_SOURCE_IPV4;
                    SrcIPv4Count++;
                }
            }
            else if (strcmp(Name, "dst ipv4") == 0)
            {
                AddressBuffer = Value;
                while ((CurrentAddress = strsep(&AddressBuffer, ",")) != NULL &&
                       (DstIPv4Count < MAX_ADDRESS_COUNT))
                {
                    strncpy(Address, CurrentAddress, strlen(CurrentAddress));
                    Address[strlen(CurrentAddress)] = '\0';
                    trim_line(Address);
                    
                    DstIPv4[DstIPv4Count] = inet_addr(Address);
                    if (DstIPv4[DstIPv4Count] == (in_addr_t)(-1))
                    {
                        printf("Line %d: Destination IPv4 Error !\n", CurrentLine);
                        return -1;
                    }
                    Flags |= MODIFY_DESTINATION_IPV4;
                    DstIPv4Count++;
                }
            }
            else if (strcmp(Name, "src mac") == 0)
            {
                AddressBuffer = Value;
                while ((CurrentAddress = strsep(&AddressBuffer, ",")) != NULL &&
                       (SrcMacCount < MAX_ADDRESS_COUNT))
                {
                    strncpy(Address, CurrentAddress, strlen(CurrentAddress));
                    Address[strlen(CurrentAddress)] = '\0';
                    trim_line(Address);
                    
                    if (string_to_mac_addr(Address, &SrcMac[SrcMacCount]) == false)
                    {
                        printf("Line %d: Source MAC Error !\n", CurrentLine);
                        return -1;
                    }
                    Flags |= MODIFY_SOURCE_MAC;
                    SrcMacCount++;
                }
            }
            else if (strcmp(Name, "dst mac") == 0)
            {
                AddressBuffer = Value;
                while ((CurrentAddress = strsep(&AddressBuffer, ",")) != NULL &&
                       (DstMacCount < MAX_ADDRESS_COUNT))
                {
                    strncpy(Address, CurrentAddress, strlen(CurrentAddress));
                    Address[strlen(CurrentAddress)] = '\0';
                    trim_line(Address);
                    
                    if (string_to_mac_addr(Address, &DstMac[DstMacCount]) == false)
                    {
                        printf("Line %d: Destination MAC Error !\n", CurrentLine);
                        return -1;
                    }
                    Flags |= MODIFY_DESTINATION_MAC;
                    DstMacCount++;
                }
            }
            else if (strcmp(Name, "rep") == 0)
            {
                Rep = strtoul(Value, NULL, 10);
                if (Rep == ULONG_MAX || Rep <= 0)
                {
                    printf("Line %d: Packet Repetation Value Error !\n", CurrentLine);
                    return -1;
                }
            }
            else
            {
                printf("Line %d: Unknown Entry !\n", CurrentLine);
                return -1;
            }
        }
        
        // Check if 'pkt buf' entry exists or not
        if (PacketBufferLength == 0)
        {
            printf("Error: Entry Doesn't Contain 'pkt buf' Entry !\n");
            return -1;
        }
        
        // Section End, Generate Packets
        size_t Maximum = MAX(SrcMacCount, DstMacCount);
        Maximum = MAX(Maximum, SrcIPv4Count);
        Maximum = MAX(Maximum, DstIPv4Count);
        
        for (i = 0; i < Maximum; i++)
        {
            if (i >= SrcMacCount) Flags &= ~MODIFY_SOURCE_MAC;
            if (i >= SrcIPv4Count) Flags &= ~MODIFY_SOURCE_IPV4;
            if (i >= DstMacCount) Flags &= ~MODIFY_DESTINATION_MAC;
            if (i >= DstIPv4Count) Flags &= ~MODIFY_DESTINATION_IPV4;
            
            for (j = 0; j < Rep; j++)
            {
                if (write_packet(&DstMac[i], DstIPv4[i], &SrcMac[i], SrcIPv4[i], PacketBuffer, PacketBufferLength, Flags, PcapOutput) == false)
                {
                    printf("Error: Unable to write packet !\n");
                    return -5;
                }
                PacketWritten++;
            }
        }
    }
    
    printf("Success: %lu Packets Written, File Size: %ld Bytes.\n", PacketWritten, ftell(PcapOutput));
    fflush(PcapOutput);
    fclose(PcapOutput);
    return 0;
}
