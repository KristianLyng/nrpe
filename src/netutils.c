/****************************************************************************
 *
 * NETUTILS.C - NRPE Network Utilities
 * Copyright (c) 1999-2001 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 * Last Modified: 06-23-2001
 *
 * Description:
 *
 * This file contains common network functions used in nrpe and check_nrpe.
 *
 * License Information:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************************/

#include "../common/common.h"
#include "netutils.h"

extern int socket_timeout;    /* this doesn't have to be used, but it is nice to know how many seconds we timed out after */

extern int errno;


/* handles socket timeouts */
void socket_timeout_alarm_handler(int sig){

	printf("Socket timeout after %d seconds\n",socket_timeout);

	exit(STATE_CRITICAL);
        }


/* connects to a host on a specified TCP port, sends a string, and gets a response */
int process_tcp_request(char *server_address, int server_port, char *send_buffer, char *recv_buffer, int recv_size){
	int result;

	result=process_request(server_address,server_port,"tcp",send_buffer,recv_buffer,recv_size);

	return result;
        }


/* connects to a host on a specified UDP port, sends a string, and gets a response */
int process_udp_request(char *server_address, int server_port, char *send_buffer, char *recv_buffer, int recv_size){
	int result;

	result=process_request(server_address,server_port,"udp",send_buffer,recv_buffer,recv_size);

	return result;
        }


/* connects to a host on a specified port, sends a string, and gets a response */
int process_request(char *server_address, int server_port, char *proto, char *send_buffer, char *recv_buffer, int recv_size){
	int result;
	int send_result;
	int recv_result;
	int sd;
	struct timeval tv;
	fd_set readfds;

	result=STATE_OK;

	result=my_connect(server_address,server_port,&sd,proto);
	if(result!=STATE_OK)
		return STATE_CRITICAL;

	send_result=send(sd,send_buffer,strlen(send_buffer),0);
	if(send_result!=strlen(send_buffer)){
		printf("send() failed\n");
		result=STATE_WARNING;
	        }

	/* wait up to the number of seconds for socket timeout minus one for data from the host */
	tv.tv_sec=socket_timeout-1;
	tv.tv_usec=0;
	FD_ZERO(&readfds);
	FD_SET(sd,&readfds);
	select(sd+1,&readfds,NULL,NULL,&tv);

	/* make sure some data has arrived */
	if(!FD_ISSET(sd,&readfds)){
		strcpy(recv_buffer,"");
		printf("No data was recieved from host!\n");
		result=STATE_WARNING;
	        }

	else{
		recv_result=recv(sd,recv_buffer,recv_size-1,0);
		if(recv_result==-1){
			strcpy(recv_buffer,"");
			if(!strcmp(proto,"tcp"))
				printf("recv() failed\n");
			result=STATE_WARNING;
	                }
		else
			recv_buffer[recv_result]='\x0';

		/* terminate returned string */
		recv_buffer[recv_size-1]='\x0';
	        }

	close(sd);

	return result;
        }


/* opens a connection to a remote host/tcp port */
int my_tcp_connect(char *host_name,int port,int *sd){
	int result;

	result=my_connect(host_name,port,sd,"tcp");

	return result;
        }


/* opens a connection to a remote host/udp port */
int my_udp_connect(char *host_name,int port,int *sd){
	int result;

	result=my_connect(host_name,port,sd,"udp");

	return result;
        }


/* opens a tcp or udp connection to a remote host */
int my_connect(char *host_name,int port,int *sd,char *proto){
	struct sockaddr_in servaddr;
	struct hostent *hp;
	struct protoent *ptrp;
	int result;

	bzero((char *)&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);

	/* try to bypass using a DNS lookup if this is just an IP address */
	if(!my_inet_aton(host_name,&servaddr.sin_addr)){

		/* else do a DNS lookup */
		hp=gethostbyname((const char *)host_name);
		if(hp==NULL){
			printf("Invalid host name '%s'\n",host_name);
			return STATE_UNKNOWN;
		        }

		memcpy(&servaddr.sin_addr,hp->h_addr,hp->h_length);
	        }

	/* map transport protocol name to protocol number */
	if(((int)(ptrp=getprotobyname(proto)))==(int)0){
		printf("Cannot map \"%s\" to protocol number\n",proto);
		return STATE_UNKNOWN;
	        }

	/* create a socket */
	*sd=socket(PF_INET,(!strcmp(proto,"udp"))?SOCK_DGRAM:SOCK_STREAM,ptrp->p_proto);
	if(*sd<0){
		printf("Socket creation failed\n");
		return STATE_UNKNOWN;
	        }

	/* open a connection */
	result=connect(*sd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	if(result<0){
		switch(errno){  
		case ECONNREFUSED:
			printf("Connection refused by host\n");
			break;
		case ETIMEDOUT:
			printf("Timeout while attempting connection\n");
			break;
		case ENETUNREACH:
			printf("Network is unreachable\n");
			break;
		default:
			printf("Connection refused or timed out\n");
		        }

		return STATE_CRITICAL;
	        }

	return STATE_OK;
        }



/* This code was taken from Fyodor's nmap utility, which was originally taken from
   the GLIBC 2.0.6 libraries because Solaris doesn't contain the inet_aton() funtion. */
int my_inet_aton(register const char *cp, struct in_addr *addr){
	register unsigned int val;	/* changed from u_long --david */
	register int base, n;
	register char c;
	u_int parts[4];
	register u_int *pp = parts;

	c=*cp;

	for(;;){

		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit((int)c))
			return (0);
		val=0;
		base=10;

		if(c=='0'){
			c=*++cp;
			if(c=='x'||c=='X')
				base=16,c=*++cp;
			else
				base=8;
		        }

		for(;;){
			if(isascii((int)c) && isdigit((int)c)){
				val=(val*base)+(c -'0');
				c=*++cp;
			        } 
			else if(base==16 && isascii((int)c) && isxdigit((int)c)){
				val=(val<<4) | (c+10-(islower((int)c)?'a':'A'));
				c = *++cp;
			        } 
			else
				break;
		        }

		if(c=='.'){

			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if(pp>=parts+3)
				return (0);
			*pp++=val;
			c=*++cp;
		        } 
		else
			break;
	        }

	/* Check for trailing characters */
	if(c!='\0' && (!isascii((int)c) || !isspace((int)c)))
		return (0);

	/* Concoct the address according to the number of parts specified */
	n=pp-parts+1;
	switch(n){

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if(val>0xffffff)
			return (0);
		val|=parts[0]<<24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if(val>0xffff)
			return (0);
		val|=(parts[0]<< 24) | (parts[1]<<16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if(val>0xff)
			return (0);
		val|=(parts[0]<<24) | (parts[1]<<16) | (parts[2]<<8);
		break;
	        }

	if(addr)
		addr->s_addr=htonl(val);

	return (1);
        }


void strip(char *buffer){
	int x;
	int index;

	for(x=strlen(buffer);x>=1;x--){
		index=x-1;
		if(buffer[index]==' ' || buffer[index]=='\r' || buffer[index]=='\n' || buffer[index]=='\t')
			buffer[index]='\x0';
		else
			break;
	        }

	return;
        }
