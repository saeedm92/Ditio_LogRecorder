/*
 * Configuration start logging app
 * File: config_app_start.c
 *
 * Copyright (c) 2017 University of California, Irvine, CA, USA
 * All rights reserved.
 *
 * Authors: Saeed Mirzamohammadi <saeed@uci.edu>
 * Ardalan Amiri Sani   <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>

/* ioctl */
#define LOGME_ON       5
#define LOGME_OFF      1
#define LOGME_GET_KEY		124
#define LOGME_SYNC_TIME		125

#define LOG_TYPE_W		0
#define LOG_TYPE_RW		1
#define SERVER_PORT		1234

int logMe_fd;

struct logme_log_ioctl {
	unsigned long pfn;
	int log_type;
	int num_pages;
};

int remote_attestion(int fd)
{
	int ret, i;
	unsigned char enc_key[16];
	unsigned char buf[512];
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	portno = SERVER_PORT;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("Error opening socket\n");
		return -1;
	} 
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = inet_addr("128.195.54.63");

	ret = ioctl(fd, LOGME_GET_KEY, buf);
	if (ret < 0) {
		printf("Failed to get key\n");
		return -1;
	}

	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
		printf("Error connecting\n");
		return -1;
	}

	n = write(sockfd, buf, 512);
	if ( n < 0 ) {
		printf("Unable to write to socket\n");
		return -1;
	}

	n = read(sockfd, enc_key, 32);
	if ( n < 0 ) {
		printf("Unable to read time from server\n");
		return -1;
	}

	ret = ioctl(fd, LOGME_SYNC_TIME, enc_key);
	if (ret < 0) {
		printf("Failed to sync time\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret;	
	struct logme_log_ioctl data;

	logMe_fd = open("/dev/logMe", 0);
	if (logMe_fd < 0) {
		printf("Can't open device file: %d\n", logMe_fd);
		return -1;
	}
//	data.pfn = 0xFE12F; /* mic register page */	
	data.pfn = 0xFDA04; /* camera register page */
	data.log_type = LOG_TYPE_RW;
	data.num_pages = 1;

	if ( argc!= 2 ) {
		printf ("Not enough input\n");
	}
	else {
		if (!strcmp(argv[1], "1"))
			goto start_logging;
		else if (!strcmp(argv[1], "2"))
			goto stop_logging;
		else
			goto exit;
	}

start_logging:	
	printf("Start logging\n");
//	ret = remote_attestion(fd);
//	if (ret < 0)
//	{
//		//printf("unable to do attestation\n");
//		goto exit;
//	}
//	printf("Remote Attestation done\n");
	
	ret = ioctl(logMe_fd, LOGME_ON, &data);
	
	while(1)
		sleep(600);
stop_logging:
	printf("Stop logging\n");
	ret = ioctl(logMe_fd, LOGME_OFF, &data);
	
exit:
	close(logMe_fd);
	return 1;
}

