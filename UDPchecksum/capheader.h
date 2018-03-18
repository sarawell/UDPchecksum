#pragma once
#include "stdafx.h"
#include "string.h"
#include"stdlib.h"
#include "time.h"
#include "winsock2.h"
#include "Ws2tcpip.h"
#pragma comment(lib,"ws2_32.lib")



////test
#define BUFSIZE	10240
#define STRSIZE	1024
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

struct pcap_file_header	//����pcap�ļ�ͷ
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
	long tv_sec;         /* seconds ����ͬ time_t �����ֵ */
	long tv_usec;        /* and microseconds */
};
//pcap���ݰ�ͷ�ṹ��

struct pcap_pkthdr
{
	struct time_val ts;  /* time stamp */
	bpf_u_int32 caplen; /* length of portion present */
	bpf_u_int32 len;    /* length this packet (off wire) */
};
typedef struct FramHeader_t
{ //Pcap���������֡ͷ
	u_int8 DstMAC[6]; //Ŀ��MAC��ַ
	u_int8 SrcMAC[6]; //ԴMAC��ַ
	u_short FrameType;    //֡����
} FramHeader_t;

//IP���ݱ�ͷ

typedef struct IPHeader_t
{ //IP���ݱ�ͷ
	u_int8 Ver_HLen;       //�汾+��ͷ����
	u_int8 TOS;            //��������
	u_int16 TotalLen;       //�ܳ���
	u_int16 ID; //��ʶ
	u_int16 Flag_Segment;   //��־+Ƭƫ��
	u_int8 TTL;            //��������
	u_int8 Protocol;       //Э������
	u_int16 Checksum;       //ͷ��У���
	u_int32 SrcIP; //ԴIP��ַ
	u_int32 DstIP; //Ŀ��IP��ַ
} IPHeader_t;
typedef struct TCPHeader_t
{ //TCP���ݱ�ͷ
	u_int16 SrcPort; //Դ�˿�
	u_int16 DstPort; //Ŀ�Ķ˿�
	u_int32 SeqNO; //���
	u_int32 AckNO; //ȷ�Ϻ�
	u_int8 HeaderLen; //���ݱ�ͷ�ĳ���(4 bit) + ����(4 bit)
	u_int8 Flags; //��ʶTCP��ͬ�Ŀ�����Ϣ
	u_int16 Window; //���ڴ�С
	u_int16 Checksum; //У���
	u_int16 UrgentPointer;  //��ָ��
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
		printf("%02x", a[j]);
	}
	printf("\n");
	unsigned long sum = 0;

	while (len > 1) {
		sum += ((*a)<<8);
		printf("%02x",*a);
		*a++;
		len--;
		sum += (*a);
		printf("%02x", *a);
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