#pragma once
#include "stdafx.h"
#include "string.h"
#include"stdlib.h"
#include "time.h"
#include "winsock2.h"
#include "Ws2tcpip.h"
#pragma comment(lib,"ws2_32.lib")




#define BUFSIZE	10240
#define STRSIZE	1024
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

struct pcap_file_header	//定义pcap文件头
{
	bpf_u_int32 magic;       /* 0xa1b2c3d4 */
	u_short version_major;   /* magjor Version 2 */
	u_short version_minor;   /* magjor Version 4 */
	bpf_int32 thiszone;      /* gmt to local correction */
	bpf_u_int32 sigfigs;     /* accuracy of timestamps */
	bpf_u_int32 snaplen;     /* max length saved portion of each pkt */
	bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */
};
struct time_val
{
	long tv_sec;         /* seconds 含义同 time_t 对象的值 */
	long tv_usec;        /* and microseconds */
};
//pcap数据包头结构体

struct pcap_pkthdr
{
	struct time_val ts;  /* time stamp */
	bpf_u_int32 caplen; /* length of portion present */
	bpf_u_int32 len;    /* length this packet (off wire) */
};
typedef struct FramHeader_t
{ //Pcap捕获的数据帧头
	u_int8 DstMAC[6]; //目的MAC地址
	u_int8 SrcMAC[6]; //源MAC地址
	u_short FrameType;    //帧类型
} FramHeader_t;

//IP数据报头

typedef struct IPHeader_t
{ //IP数据报头
	u_int8 Ver_HLen;       //版本+报头长度
	u_int8 TOS;            //服务类型
	u_int16 TotalLen;       //总长度
	u_int16 ID; //标识
	u_int16 Flag_Segment;   //标志+片偏移
	u_int8 TTL;            //生存周期
	u_int8 Protocol;       //协议类型
	u_int16 Checksum;       //头部校验和
	u_int32 SrcIP; //源IP地址
	u_int32 DstIP; //目的IP地址
} IPHeader_t;
typedef struct TCPHeader_t
{ //TCP数据报头
	u_int16 SrcPort; //源端口
	u_int16 DstPort; //目的端口
	u_int32 SeqNO; //序号
	u_int32 AckNO; //确认号
	u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
	u_int8 Flags; //标识TCP不同的控制消息
	u_int16 Window; //窗口大小
	u_int16 Checksum; //校验和
	u_int16 UrgentPointer;  //紧急指针
}TCPHeader_t;


typedef struct UDPHeader_t
{
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int16 PayLen;
	u_int16 Checksum;
}UDPHeader_t;

typedef struct UDP_H
{
	u_int32 SrcIP;
	u_int32 DstIP;
	u_int8	mbz;
	u_int8 Protocol;
	u_int16 PayLen;
}UDP_H;

unsigned short check_sum(unsigned char *a, int len)
{
	for (int j = 0; j < len; j++)
	{
		//printf("%02x", a[j]);
	}
	//printf("\n");
	unsigned long sum = 0;

	while (len > 1) {
		sum += ((*a)<<8);
		//printf("%02x",*a);
		*a++;
		len--;
		sum += (*a);
		//printf("%02x", *a);
		*a++;
		len--;
		
	}

	if (len) {
		sum += (*a)<<8;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}

	return (unsigned short)(~sum);
}