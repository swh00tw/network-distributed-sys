#include "gbn.h"

state_t s = {CLOSED};
struct sockaddr *recv_addr;
socklen_t recv_addrlen;
struct sockaddr *send_addr;
socklen_t send_addrlen;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* TODO
 1. seq num
 2. solve the NULL problem
 3. go back N */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	size_t chunk_size = len > DATALEN ? DATALEN : len;
	while (len > 0){
		gbnhdr *data = malloc(sizeof(gbnhdr));
		memset(data, 0, sizeof(gbnhdr));

		data->type = DATA;
		data->seqnum = 123;
		memcpy(data->data, buf, chunk_size);
		data->checksum = checksum((uint16_t *)data, sizeof(gbnhdr)/2);
		ssize_t bytes_sent = sendto(sockfd, data, sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			return -1;
		}
		
		gbnhdr *ack = malloc(sizeof(gbnhdr));
		memset(ack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = recvfrom(sockfd, ack, sizeof(gbnhdr), 0, NULL, NULL);
		if (bytes_recv == -1){
			perror("recvfrom failed");
			return -1;
		}

		uint16_t checksum_recv = ack->checksum;
		ack->checksum = 0;
		if (ack->type != DATAACK || checksum_recv != checksum((uint16_t *)ack, sizeof(gbnhdr)/2)){
			perror("DATAACK packet corrupted\n");
			return -1;
		}

		free(data);
		free(ack);

		len -= chunk_size;
		buf += chunk_size;
		chunk_size = len > DATALEN ? DATALEN : len;
	}

	/* send FIN */
	gbnhdr *fin = malloc(sizeof(gbnhdr));
	memset(fin, 0, sizeof(gbnhdr));
	fin->type = FIN;
	fin->seqnum = 5;
	fin->checksum = checksum((uint16_t *)fin, sizeof(gbnhdr)/2);
	ssize_t bytes_sent = sendto(sockfd, fin, sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		return -1;
	}
	printf("Send FIN bytes_sent: %d\n", (int) bytes_sent);

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	gbnhdr *data = malloc(sizeof(gbnhdr));
	memset(data, 0, sizeof(gbnhdr));

	ssize_t bytes_recv = recvfrom(sockfd, data, sizeof(gbnhdr), 0, NULL, NULL);
	if (bytes_recv == -1){
		perror("recvfrom failed");
		return -1;
	}

	uint16_t checksum_recv = data->checksum;
	data->checksum = 0;
	if (checksum_recv != checksum((uint16_t *)data, sizeof(gbnhdr)/2)) {
		perror("DATA packet corrupted\n");
		return -1;
	}

	if (data->type == FIN) {
		free(data);
		return 0;
	}

	if (data->type != DATA) {
		perror("DATA packet corrupted\n");
		return -1;
	}

	gbnhdr *ack = malloc(sizeof(gbnhdr));
	memset(ack, 0, sizeof(gbnhdr));
	ack->type = DATAACK;
	ack->seqnum = 5;
	ack->checksum = checksum((uint16_t *)ack, sizeof(gbnhdr)/2);
	ssize_t bytes_sent = sendto(sockfd, ack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		return -1;
	}
	/* write data to buf */
	memcpy(buf, data->data, len);
	printf("Receive DATA bytes_recv: %d\n", (int) bytes_recv);
	/* print buf */
	printf("buf: %s\n", (char *)buf);

	free(data);
	free(ack);

	return len;
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	return close(sockfd);;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	/* Send SYN */
	gbnhdr *syn = malloc(sizeof(gbnhdr));
	memset(syn, 0, sizeof(gbnhdr));
	
	/* Construct SYN packet */
	syn->type = SYN;
	syn->seqnum = 0;
	syn->checksum = checksum((uint16_t *)syn, sizeof(gbnhdr)/2);
	
	/* Send SYN packet */
	ssize_t bytes_sent = sendto(sockfd, syn, sizeof(gbnhdr), 0, server, socklen);
	s.state = SYN_SENT;
	
	/* Free memory */
	free(syn);

	/* Receive SYNACK */
	/* Allocate memory */
	gbnhdr *synack = malloc(sizeof(gbnhdr));
	memset(synack, 0, sizeof(gbnhdr));

	/* Receive SYNACK packet */
	ssize_t bytes_recv = recvfrom(sockfd, synack, sizeof(gbnhdr), 0, NULL, NULL);
	
	/* Check if SYNACK packet is corrupted */
	uint16_t checksum_recv = synack->checksum;
	synack->checksum = 0;
	if (synack->type != SYNACK || synack->seqnum != 0 || checksum_recv != checksum((uint16_t *)synack, sizeof(gbnhdr)/2)){
		free(synack);
		perror("SYNACK packet corrupted\n");
		return -1;
	}

	/* Free memory */
	free(synack);

	/* Set Receiver address */
	recv_addr = (struct sockaddr *) server;
	recv_addrlen = socklen;
	s.state = ESTABLISHED;

	
	return 0;
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	/* Receive SYN */
	/* Allocate memory */
	gbnhdr *syn = malloc(sizeof(gbnhdr));
	memset(syn, 0, sizeof(gbnhdr));

	/* Receive SYN packet */
	ssize_t bytes_recv = recvfrom(sockfd, syn, sizeof(gbnhdr), 0, client, socklen);
	
	/* Check if SYN packet is corrupted */
	uint16_t checksum_recv = syn->checksum;
	syn->checksum = 0;
	if (syn->type != SYN || syn->seqnum != 0 || checksum_recv != checksum((uint16_t *)syn, sizeof(gbnhdr)/2)){
		free(syn);
		perror("SYN packet corrupted\n");
		return -1;
	}
	s.state = SYN_RCVD;

	/* Free memory */
	free(syn);
	

	/* Send SYNACK */
	/* Allocate memory */
	gbnhdr *synack = malloc(sizeof(gbnhdr));
	memset(synack, 0, sizeof(gbnhdr));

	/* Construct SYNACK packet */
	synack->type = SYNACK;
	synack->seqnum = 0;
	synack->checksum = checksum((uint16_t *)synack, sizeof(gbnhdr)/2);
	
	/* Send SYNACK packet */
	ssize_t bytes_sent = sendto(sockfd, synack, sizeof(gbnhdr), 0, client, *socklen);
	
	/* Free memory */
	free(synack);

	/* Set Sender address */
	send_addr = client;
	send_addrlen = *socklen;

	return sockfd;
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
