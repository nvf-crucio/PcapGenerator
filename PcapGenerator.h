#ifndef PCAP_GENERATOR_INCLUDED
#define PCAP_GENERATOR_INCLUDED

#define ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */

#define VERSION                     "v0.1"

#define MAX_INPUT_LINE              (32 * 1024)   // 32 KB - Single Line
#define MAXIMUM_PACKET_SIZE         (MAX_INPUT_LINE / 3)
#define MAX_ADDRESS                 64
#define MAX_ADDRESS_COUNT           128

#define MODIFY_SOURCE_MAC           (1 << 0)
#define MODIFY_SOURCE_IPV4          (1 << 1)
#define MODIFY_DESTINATION_MAC      (1 << 2)
#define MODIFY_DESTINATION_IPV4     (1 << 3)

#ifndef MAX
 #define MAX(a,b) (((a)>(b))?(a):(b))
#endif

struct ether_addr {
	uint8_t addr_bytes[ETHER_ADDR_LEN]; /**< Address bytes in transmission order */
} __attribute__((__packed__));

struct ether_hdr {
	struct ether_addr _d_addr; /**< Destination address. */
	struct ether_addr _s_addr; /**< Source address. */
	uint16_t ether_type;      /**< Frame type. */
} __attribute__((__packed__));

struct ipv4_hdr {
	uint8_t  version_ihl;		/**< version and header length */
	uint8_t  type_of_service;	/**< type of service */
	uint16_t total_length;		/**< length of packet */
	uint16_t packet_id;		/**< packet ID */
	uint16_t fragment_offset;	/**< fragmentation offset */
	uint8_t  time_to_live;		/**< time to live */
	uint8_t  next_proto_id;		/**< protocol ID */
	uint16_t hdr_checksum;		/**< header checksum */
	uint32_t src_addr;		/**< source address */
	uint32_t dst_addr;		/**< destination address */
} __attribute__((__packed__));

struct pcap_hdr{
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} __attribute__((__packed__));

struct pcaprec_hdr {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} __attribute__((__packed__));

typedef struct {
    char *Name;
    unsigned int PacketSize;
    const unsigned char *PacketBuffer;
} PacketTemplate;

#endif // PCAP_GENERATOR_INCLUDED
