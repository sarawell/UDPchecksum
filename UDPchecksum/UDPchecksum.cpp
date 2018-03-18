// UDPchecksum.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "stdio.h"
//#include"unistd.h"
#include "Ws2tcpip.h"
#pragma comment(lib, "Ws2_32.lib")
#include "capheader.h"





int main()
{
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *ptk_header;
	FramHeader_t *fheader;
	IPHeader_t *ip_header;
	UDPHeader_t *udp_header;
	UDP_H *udp_h;
	FILE *fr, *fw;


	file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
	
	fr = fopen("test.pcap", "rb");
	if (fr == NULL)
	{
		printf("文件打开失败\n");
		exit(0);
	}

	if (fread(file_header, 24, 1, fr) != 1)//读取文件头
	{
		printf("文件头读取失败\n");
		exit(0);
	}
	//int cc = 40;
	//while (cc>0)
	if(!feof(fr))
	{
		ptk_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
		fheader = (FramHeader_t *)malloc(sizeof(FramHeader_t));
		ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
		udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
		udp_h = (UDP_H*)malloc(sizeof(UDP_H));
		int buff_size = 0;
		fread(ptk_header, 16, 1, fr);
		buff_size = ptk_header->caplen;
		u_char* buff = (u_char*)malloc(buff_size);
		fread(buff, buff_size, 1, fr);
		//for (int i = 0; i < buff_size; i++)
		//{
		//	printf("%02x", buff[i]);
		//	//printf("\n");
		//}
		memset(fheader, 0x00, sizeof(FramHeader_t));
		memcpy(fheader, (u_char*)buff, sizeof(FramHeader_t));
		memcpy(ip_header, (u_char*)buff + sizeof(FramHeader_t), sizeof(IPHeader_t));
		memcpy(udp_header, (u_char*)buff + sizeof(FramHeader_t) + sizeof(IPHeader_t), sizeof(UDPHeader_t));
		/*printf("\n");*/
		udp_h->DstIP = ip_header->DstIP;
		udp_h->SrcIP = ip_header->SrcIP;
		udp_h->mbz = 0x00;
		udp_h->Protocol = ip_header->Protocol;
		udp_h->PayLen = udp_header->PayLen;
		u_char* buff1 = (u_char*)malloc(ntohs(udp_header->PayLen)+sizeof(UDP_H));
		printf("%d", ntohs(udp_header->PayLen));
		memcpy(buff1, (char *)udp_h, sizeof(UDP_H));
		memcpy(buff1 + sizeof(UDP_H), (u_char*)buff + sizeof(FramHeader_t) + sizeof(IPHeader_t), buff_size- sizeof(FramHeader_t) - sizeof(IPHeader_t));
		//for (int i = 0; i < (ntohs(udp_header->PayLen) + sizeof(UDP_H)); i++)
		//{
		//	printf("%02x", buff1[i]);
		//	//printf("\n");
		//}
		//printf("\n");
		memset(buff1 + 18, 0x00, 1);
		memset(buff1 + 19, 0x00, 1);
		unsigned short sum = 0;

		sum = check_sum((unsigned char*)buff1, (ntohs(udp_header->PayLen) + sizeof(UDP_H)));
		printf("%02x", sum);
		printf("\n");
		free(buff1);
		free(buff);
		free(ptk_header);
		free(fheader);
		free(ip_header);
		free(udp_header);
		free(udp_h);
		//cc--;
	}
	return 0;
}
	//while (1)
	//{
	//	if (fread(ptk_header, 16, 1, fr) != 1)
	//	{
	//		printf("文件头读取失败\n");
	//		exit(0);
	//	}
	//	//fseek(fr, -16, SEEK_CUR);
	//	buff_size = ptk_header->caplen;
	//	u_char* buff = (u_char*)malloc(buff_size);
	//	fread(buff, buff_size, 1, fr);
	//	for (int i = 0; i < buff_size; i++)
	//	{
	//		printf("%02x", buff[i]);
	//	}
	//	printf("\n");
	//	free(buff);
	//}
	//while (1)
	//{
	//	int i;
	//	int buff_size = 0;
	//	if (fread(ptk_header, 16, 1, fr) != 1)
	//	{
	//		printf("文件头读取失败\n");
	//		exit(0);
	//	}
	//	fseek(fr, 14, SEEK_CUR);//屏蔽mac层的信息
	//	if (fread(ip_header, sizeof(IPHeader_t), 1, fr) != 1)
	//	{
	//		printf("IP头读取失败\n");
	//		exit(0);
	//	}

	//	if (fread(udp_header, sizeof(UDPHeader_t), 1, fr) != 1)
	//	{
	//		printf("UDP头读取失败\n");
	//		exit(0);
	//	}
	//	fseek(fr, -8, SEEK_CUR);
	//	unsigned char *frame;
	//	frame = (unsigned char*)malloc(ntohs(udp_header->PayLen));
	//	fread(frame, ntohs(udp_header->PayLen), 1, fr);
	//	for (int j = 0; j < ntohs(udp_header->PayLen); j++)
	//	{
	//		printf("%02x", frame[j]);
	//	}
	//	printf("\n");
	//	printf("%d\n", ntohs(udp_header->PayLen));
	//	buff_size = ntohs(udp_header->PayLen) + 12;
	//	u_char* buff = (u_char*)malloc(buff_size);
	//	memset(buff, 0x00, buff_size);
	//	udp_h->DstIP = ip_header->DstIP;
	//	udp_h->SrcIP = ip_header->SrcIP;
	//	udp_h->mbz = 0x00;
	//	udp_h->Protocol = ip_header->Protocol;
	//	udp_h->PayLen = udp_header->PayLen;
	//	memcpy(buff, (char *)udp_h, sizeof(UDP_H));
	//	for (int j = 0; j < sizeof(UDP_H); j++)
	//	{
	//		printf("%02x", buff[j]);
	//	}
	//	printf("\n");
		/*memcpy(buff + sizeof(UDP_H), (char *)udp_header, sizeof(UDPHeader_t));
		for (int j = 0; j < (sizeof(UDP_H)+ sizeof(UDPHeader_t)); j++)
		{
		printf("%02x", buff[j]);
		}
		printf("\n");*/
		/*memcpy(buff + sizeof(UDP_H), (char*)frame, ntohs(udp_header->PayLen));
		for (int j = 0; j < (sizeof(UDP_H) + ntohs(udp_header->PayLen)); j++)
		{
			printf("%02x", buff[j]);
		}
		printf("\n");
		memset(buff + 18, 0x00, 1);
		memset(buff + 19, 0x00, 1);
		for (int j = 0; j < (sizeof(UDP_H) + ntohs(udp_header->PayLen)); j++)
		{
			printf("%02x", buff[j]);
		}
		printf("\n");
		unsigned short sum = 0;

		sum = check_sum((unsigned char*)buff, buff_size);
		printf("%02x", sum);
		free(buff);
	}*/
	

//
//typedef struct {
//	int srcIp;
//	int dstIp;
//	short udp_len;
//	char rsv;
//	char protocol;
//	unsigned short src_port;
//	unsigned short dst_port;
//	unsigned short len;
//	unsigned short check_sum;
//	char data[2];
//} UDPHDR;
//char arr[100] = { 0xc0, 0xa8, 0xd1, 0x80, 0xc0, 0xa8, 0xd1, 0x01, 0x00, 0x0a, 0x00, 0x11, 0x13, 0x88, 0x13, 0x88, 0x00, 0x0a, 0x00, 0x00, 0x61, 0x66 };
//unsigned short check_sum(unsigned short *a, int len);
//
//
//
//
//int main()
//{
//	short b = 0;
//	UDPHDR udphdr = { 0 };
//
//	udphdr.srcIp = inet_addr("192.168.209.128");
//	udphdr.dstIp = inet_addr("192.168.209.1");
//	udphdr.udp_len = htons(10);
//	udphdr.protocol = 0x11;
//	udphdr.rsv = 0;
//	udphdr.src_port = htons(5000);
//	udphdr.dst_port = htons(5000);
//	udphdr.len = htons(10);
//	udphdr.check_sum = 0;
//	udphdr.data[0] = 0x61;
//	udphdr.data[1] = 0x66;
//
//	b = check_sum((unsigned short *)&udphdr, 22);
//	printf("[test ...] b = %04x\n", b & 0xffff);
//
//	b = check_sum((unsigned short *)arr, 22);
//	printf("[test arr] b = %04x\n", b & 0xffff);
//
//	return 0;
//}
//
//unsigned short check_sum(unsigned short *a, int len)
//{
//	unsigned int sum = 0;
//
//	while (len > 1) {
//		sum += *a++;
//		len -= 2;
//	}
//
//	if (len) {
//		sum += *(unsigned char *)a;
//	}
//
//	while (sum >> 16) {
//		sum = (sum >> 16) + (sum & 0xffff);
//	}
//
//	return (unsigned short)(~sum);
//}

