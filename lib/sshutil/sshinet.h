/*
  File: sshinet.h

  Authors: 
        Tero T Mononen <tmo@ssh.fi>

  Description: 
        IP protocol specific definitions

  Copyright:
        Copyright (c) 1998 SSH Communications Security, Finland
        All rights reserved
*/

#ifndef SSHIP_H
#define SSHIP_H

#include "sshenum.h"

/* Keyword mapping for IP protocol identifier numbers and names */
extern const SshKeyword ssh_ip_protocol_id_keywords[];

/* IP protocol identifiers */
typedef enum {
  IP_PROTOCOL_ID_ANY = 0,       /* Any protocol */
  IP_PROTOCOL_ID_ICMP = 1,      /* Internet Control Message [RFC792] */
  IP_PROTOCOL_ID_IGMP = 2,      /* Internet Group Mgmt [RFC1112] */
  IP_PROTOCOL_ID_GGP = 3,       /* Gateway-to-Gateway [RFC823] */
  IP_PROTOCOL_ID_IPIP = 4,      /* IP in IP [RFC2003] */
  IP_PROTOCOL_ID_ST = 5,        /* Stream [RFC1190] */
  IP_PROTOCOL_ID_TCP = 6,       /* Transmission Control [RFC793] */
  IP_PROTOCOL_ID_CBT = 7,       /* CBT [Ballardie] */
  IP_PROTOCOL_ID_EGP = 8,       /* Exterior GW Protocol [RFC888] */
  IP_PROTOCOL_ID_IGP = 9,       /* any private interior GW [IANA] */
  IP_PROTOCOL_ID_BBN = 10,      /* BBN RCC Monitoring [SGC] */
  IP_PROTOCOL_ID_NVP = 11,      /* Network Voice Protocol [RFC741] */
  IP_PROTOCOL_ID_PUP = 12,      /* PUP [PUP XEROX] */
  IP_PROTOCOL_ID_ARGUS = 13,    /* ARGUS [RWS4] */
  IP_PROTOCOL_ID_EMCON = 14,    /* EMCON [BN7] */
  IP_PROTOCOL_ID_XNET = 15,     /* Cross Net Debugger [IEN158] */
  IP_PROTOCOL_ID_CHAOS = 16,    /* Chaos [NC3] */
  IP_PROTOCOL_ID_UDP = 17,      /* User Datagram [RFC768 JBP] */
  IP_PROTOCOL_ID_MUX = 18,      /* Multiplexing [IEN90 JBP] */
  IP_PROTOCOL_ID_DCN = 19,      /* DCN Measurement Subsystems [DLM1] */
  IP_PROTOCOL_ID_HMP = 20,      /* Host Monitoring [RFC869 RH6] */
  IP_PROTOCOL_ID_PRM = 21,      /* Packet Radio Measurement [ZSU] */
  IP_PROTOCOL_ID_XNS = 22,      /* XEROX NS IDP [ETHERNET XEROX] */
  IP_PROTOCOL_ID_TRUNK1 = 23,   /* Trunk-1 [BWB6] */
  IP_PROTOCOL_ID_TRUNK2 = 24,   /* Trunk-2 [BWB6] */
  IP_PROTOCOL_ID_LEAF1 = 25,    /* Leaf-1 [BWB6] */
  IP_PROTOCOL_ID_LEAF2 = 26,    /* Leaf-2 [BWB6] */
  IP_PROTOCOL_ID_RDP = 27,      /* Reliable Data Protocol [RFC908] */
  IP_PROTOCOL_ID_IRTP = 28,     /* Reliable Transaction  [RFC938] */
  IP_PROTOCOL_ID_ISOTP4 = 29,   /* ISO Transport [RFC905 RC77] */
  IP_PROTOCOL_ID_NETBLT = 30,   /* Bulk Data Transfer [RFC969] */
  IP_PROTOCOL_ID_MFE = 31,      /* MFE Network Services [MFENET] */
  IP_PROTOCOL_ID_MERIT = 32,    /* MERIT Internodal Protocol [HWB] */
  IP_PROTOCOL_ID_SEP = 33,      /* Sequential Exchange [JC120] */
  IP_PROTOCOL_ID_3PC = 34,      /* Third Party Connect [SAF3] */
  IP_PROTOCOL_ID_IDPR = 35,     /* InterDomain Policy Routing [MXS1] */
  IP_PROTOCOL_ID_XTP = 36,      /* XTP [GXC] */
  IP_PROTOCOL_ID_DDP = 37,      /* Datagram Delivery [WXC] */
  IP_PROTOCOL_ID_IDPRC = 38,    /* IDPR Control Msg Transport [MXS1] */
  IP_PROTOCOL_ID_TP = 39,       /* TP++ Transport [DXF] */
  IP_PROTOCOL_ID_IL = 40,       /* IL Transport [Presotto] */
  IP_PROTOCOL_ID_IPV6 = 41,     /* Ipv6 [Deering] */
  IP_PROTOCOL_ID_SDRP = 42,     /* Source Demand Routing  [DXE1] */
  IP_PROTOCOL_ID_IPV6ROUTE = 43,/* Routing Hdr for IPv6 [Deering] */
  IP_PROTOCOL_ID_IPV6FRAG = 44, /* Fragment Hdr for IPv6 [Deering] */
  IP_PROTOCOL_ID_IDRP = 45,     /* Inter-Domain Routing [Sue Hares] */
  IP_PROTOCOL_ID_RSVP = 46,     /* Reservation Protocol [Bob Braden] */
  IP_PROTOCOL_ID_GRE = 47,      /* General Routing Encapsulation */
  IP_PROTOCOL_ID_MHRP = 48,     /* Mobile Host Routing */
  IP_PROTOCOL_ID_BNA = 49,      /* BNA [Gary Salamon] */
  IP_PROTOCOL_ID_ESP = 50,      /* Encap Security Payload [RFC1827] */
  IP_PROTOCOL_ID_AH = 51,       /* Authentication Header [RFC1826] */
  IP_PROTOCOL_ID_INLSP = 52,    /* Integrated Net Layer Sec TUBA */
  IP_PROTOCOL_ID_SWIPE = 53,    /* IP with Encryption [JI6] */
  IP_PROTOCOL_ID_NARP = 54,     /* NBMA Address Resolution [RFC1735] */
  IP_PROTOCOL_ID_MOBILE = 55,   /* IP Mobility [Perkins] */
  IP_PROTOCOL_ID_TLSP = 56,     /* TLS with Kryptonet KM [Oberg] */
  IP_PROTOCOL_ID_SKIP = 57,     /* SKIP [Markson] */
  IP_PROTOCOL_ID_IPV6ICMP = 58, /* ICMP for IPv6 [RFC1883] */
  IP_PROTOCOL_ID_IPV6NONXT = 59,/* No Next Header for IPv6 [RFC1883] */
  IP_PROTOCOL_ID_IPV6OPTS = 60, /* Opts IPv6 host internal [RFC1883] */
  IP_PROTOCOL_ID_CFTP = 62,     /* CFTP [CFTP,H CF2] */
  IP_PROTOCOL_ID_LOCAL = 63,    /* local network [IANA] */
  IP_PROTOCOL_ID_SAT = 64,      /* SATNET and Backroom EXPAK [SHB] */
  IP_PROTOCOL_ID_KRYPTOLAN = 65,/* Kryptolan [PXL1] */
  IP_PROTOCOL_ID_RVD = 66,      /* MIT Remote Virtual Disk [MBG] */
  IP_PROTOCOL_ID_IPPC = 67,     /* Internet Pluribus Packet Core */
  IP_PROTOCOL_ID_DISTFS = 68,   /* Any distributed FS [IANA] */
  IP_PROTOCOL_ID_SATMON = 69,   /* SATNET Monitoring [SHB] */
  IP_PROTOCOL_ID_VISA = 70,     /* VISA Protocol [GXT1] */
  IP_PROTOCOL_ID_IPCV = 71,     /* Internet Packet Core Utility */
  IP_PROTOCOL_ID_CPNX = 72,     /* Computer Network Executive */
  IP_PROTOCOL_ID_CPHB = 73,     /* Computer Heart Beat */
  IP_PROTOCOL_ID_WSN = 74,      /* Wang Span Network [VXD] */
  IP_PROTOCOL_ID_PVP = 75,      /* Packet Video Protocol [SC3] */
  IP_PROTOCOL_ID_BRSATMON = 76, /* Backroom SATNET Monitoring [SHB] */
  IP_PROTOCOL_ID_SUNND = 77,    /* SUN ND PROTOCOL-Temporary [WM3] */
  IP_PROTOCOL_ID_WBMON = 78,    /* WIDEBAND Monitoring [SHB] */
  IP_PROTOCOL_ID_WBEXPAK = 79,  /* WIDEBAND EXPAK [SHB] */
  IP_PROTOCOL_ID_ISOIP = 80,    /* ISO Internet Protocol [MTR] */
  IP_PROTOCOL_ID_VMTP = 81,     /* VMTP [DRC3] */
  IP_PROTOCOL_ID_SECUREVMTP = 82, /* SECURE-VMTP [DRC3] */
  IP_PROTOCOL_ID_VINES = 83,    /* VINES [BXH] */
  IP_PROTOCOL_ID_TTP = 84,      /* TTP [JXS] */
  IP_PROTOCOL_ID_NSFNET = 85,   /* NSFNET-IGP [HWB] */
  IP_PROTOCOL_ID_DGP = 86,      /* Dissimilar Gateway [DGP] */
  IP_PROTOCOL_ID_TCF = 87,      /* TCF [GAL5] */
  IP_PROTOCOL_ID_EIGRP = 88,    /* EIGRP [CISCO GXS] */
  IP_PROTOCOL_ID_OSPFIGP = 89,  /* OSPFIGP [RFC1583 JTM4] */
  IP_PROTOCOL_ID_SPRITE = 90,   /* Sprite RPC [SPRITE BXW] */
  IP_PROTOCOL_ID_LARP = 91,     /* Locus Address Resolution [BXH] */
  IP_PROTOCOL_ID_MTP = 92,      /* Multicast Transport [SXA] */
  IP_PROTOCOL_ID_AX25 = 93,     /* AX.25 Frames [BK29] */
  IP_PROTOCOL_ID_IPWIP = 94,    /* IP-within-IP Encapsulation [JI6] */
  IP_PROTOCOL_ID_MICP = 95,     /* Mobile Internetworking Ctrl [JI6] */
  IP_PROTOCOL_ID_SCC = 96,      /* Semaphore Communications [HXH] */
  IP_PROTOCOL_ID_ETHERIP = 97,  /* Ethernet-within-IP Encapsulation */
  IP_PROTOCOL_ID_ENCAP = 98,    /* Encapsulation Header [RFC1241] */
  IP_PROTOCOL_ID_ENCRYPT = 99,  /* Any private encryption [IANA] */
  IP_PROTOCOL_ID_GMTP = 100,    /* GMTP [RXB5] */
  IP_PROTOCOL_ID_IFMP = 101,    /* Ipsilon Flow Management [Hinden] */
  IP_PROTOCOL_ID_PNNI = 102,    /* PNNI over IP [Callon] */
  IP_PROTOCOL_ID_PIM = 103,     /* Protocol Independent Multicast */
  IP_PROTOCOL_ID_ARIS = 104,    /* ARIS [Feldman] */
  IP_PROTOCOL_ID_SCPS = 105,    /* SCPS [Durst] */
  IP_PROTOCOL_ID_QNX = 106,     /* QNX [Hunter] */
  IP_PROTOCOL_ID_AN = 107,      /* Active Networks [Braden] */
  IP_PROTOCOL_ID_IPPCP = 108,   /* IP Payload Compr Protocol */
  IP_PROTOCOL_ID_SNP = 109,     /* Sitara Networks Protocol */
  IP_PROTOCOL_ID_COMPAQ = 110,  /* Compaq Peer Protocol */
  IP_PROTOCOL_ID_IPXIP = 111,   /* IPX in IP [Lee] */
  IP_PROTOCOL_ID_VRRP = 112,    /* Virtual Router Redundancy */
  IP_PROTOCOL_ID_PGM = 113,     /* PGM Reliable Transport */
  IP_PROTOCOL_ID_0HOP = 114,    /* Any 0-hop protocol [IANA] */
  IP_PROTOCOL_ID_L2TP = 115,    /* Layer Two Tunneling [Aboba] */
  IP_PROTOCOL_ID_RESERVED = 255 /* Reserved [IANA] */
} SshInetIPProtocolID;

#define IP_PROTOCOL_ID_MIN (  0)
#define IP_PROTOCOL_ID_MAX (255)
#define IP_PROTOCOL_ID_MAX (255)

/* IP protocol identifiers */
typedef enum {
  IP_ICMP_TYPE_ECHOREPLY = 0,           /* Echo reply */
  IP_ICMP_TYPE_UNREACH = 3,             /* Destination unreachable */
  IP_ICMP_TYPE_SOURCEQUENCH = 4,        /* Congestion slow down */
  IP_ICMP_TYPE_REDIRECT = 5,            /* Shorter route */
  IP_ICMP_TYPE_ECHO = 8,                /* Echo service */
  IP_ICMP_TYPE_ROUTERADVERT = 9,        /* Router advertisement */
  IP_ICMP_TYPE_ROUTERSOLICIT = 10,      /* Router solicitation */
  IP_ICMP_TYPE_TIMXCEED = 11,           /* Time exceeded */
  IP_ICMP_TYPE_PARAMPROB = 12,          /* Ip header bad */
  IP_ICMP_TYPE_TSTAMP = 13,             /* Timestamp request */
  IP_ICMP_TYPE_TSTAMPREPLY = 14,        /* Timestamp reply */
  IP_ICMP_TYPE_IREQ = 15,               /* Information request */
  IP_ICMP_TYPE_IREQREPLY = 16,          /* Information reply */
  IP_ICMP_TYPE_MASKREQ = 17,            /* Address mask request */
  IP_ICMP_TYPE_MASKREPLY = 18           /* Address mask reply */
} SshInetIPIcmpType;

typedef enum {
  IP_ICMP_CODE_UNREACH_NET = 0,         /* Bad network */
  IP_ICMP_CODE_UNREACH_HOST = 1,        /* Bad host */
  IP_ICMP_CODE_UNREACH_PROTOCOL = 2,    /* Bad protocol */
  IP_ICMP_CODE_UNREACH_PORT = 3,        /* Bad port */
  IP_ICMP_CODE_UNREACH_NEEDFRAG = 4,    /* IP_DF caused drop, frag needed */
  IP_ICMP_CODE_UNREACH_SRCFAIL = 5,     /* Src route failed */
  IP_ICMP_CODE_UNREACH_NET_UNKNOWN = 6, /* Unknown net */
  IP_ICMP_CODE_UNREACH_HOST_UNKNOWN = 7,/* Unknown host */
  IP_ICMP_CODE_UNREACH_ISOLATED = 8,    /* Src host is isolated */
  IP_ICMP_CODE_UNREACH_NET_PROHIB = 9,  /* Prohibited network access */
  IP_ICMP_CODE_UNREACH_HOST_PROHIB = 10,/* Prohibited host access */
  IP_ICMP_CODE_UNREACH_TOSNET = 11,     /* Bad TOS for net */
  IP_ICMP_CODE_UNREACH_TOSHOST = 12,    /* Bad TOS for host */
  IP_ICMP_CODE_UNREACH_ADMIN_PROHIBIT = 13   /* Communication prohibited */
} SshInetIPIcmpUnreachCode;

#define IP_ICMP_MINLEN  8

typedef enum {
  IP_ICMP_CODE_REDIRECT_NET = 0,        /* Redirect for network */
  IP_ICMP_CODE_REDIRECT_HOST = 1,       /* ... for host */
  IP_ICMP_CODE_REDIRECT_TOSNET = 2,     /* ... for TOS and net */
  IP_ICMP_CODE_REDIRECT_TOSHOST = 3     /* ... for TOS and host */
} SshInetIPIcmpRedirecCode;

typedef enum {
  IP_ICMP_CODE_TIMXCEED_INTRANS = 0,    /* TTL becomes zero in transit */
  IP_ICMP_CODE_TIMXCEED_REASS = 1       /* TTL becomes zero in reassembly */
} SshInetIPIcmpTimexceedCode;

/* --------------------- auxiliary functions -------------------------*/

/* Determines whether the given string is a valid numeric IP address.
   (This currently only works for IPv4 addresses, but might be changed
   in future to accept also IPv6 addresses on systems that support
   them. */
Boolean ssh_inet_is_valid_ip_address(const char *address);

/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense). */
int ssh_inet_ip_address_compare(const char *address1, const char *address2);

/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */
Boolean ssh_inet_compare_netmask(const char *netmask, const char *ip);

/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion successful and FALSE
   otherwise. */
Boolean ssh_inet_strtobin(const char *ip_address, unsigned char *out_buffer,
                          size_t *out_buffer_len_in_out);

/* Internal functions.  These should not be called by normal
   applications. */
char *ssh_inet_v4tostr(char *buf, size_t len, SshUInt32 addr);
Boolean ssh_inet_strtov4(const char *buf, SshUInt32 *paddr);

#endif /* SSHIP_H */
