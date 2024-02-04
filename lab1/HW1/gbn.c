#include "gbn.h"

state_t s;
int SYN_RETRIES = 5;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* DONE: Your code here. */
	int retry = 0;
	gbnhdr syn_pkt;
	/* prepare the SYN packet */
	memset(&syn_pkt, 0, sizeof(syn_pkt));
	syn_pkt.type = SYN;
	int numberofwords = sizeof(syn_pkt)/2; /* convert bytes to words */ 
	syn_pkt.checksum = checksum((uint16_t *)&syn_pkt, numberofwords); 

	s.state = SYN_SENT;
	while (retry < SYN_RETRIES){
		/* Send SYN packet */ 
		if (maybe_sendto(sockfd, &syn_pkt, sizeof(syn_pkt), 0, server, socklen) < 0) {
				perror("Failed to send SYN packet");
				return -1;
		}
		/* Wait for SYN-ACK */ 
		gbnhdr syn_ack_pkt;
		if (maybe_recvfrom(sockfd, &syn_ack_pkt, sizeof(syn_ack_pkt), 0, NULL, NULL) < 0) {
				perror("Failed to receive SYN-ACK packet");
				return -1;
		}
		/* Check if the received packet is a SYN-ACK packet */
		if (syn_ack_pkt.type != SYNACK || checksum((uint16_t *)&syn_ack_pkt, sizeof(syn_ack_pkt)/2) != 0) {
			retry++;
		} else {
			break;
		}
	}

	/* Update state to ESTABLISHED */ 
	s.state = ESTABLISHED;
	return 0;
}

int gbn_listen(int sockfd, int backlog){

	/* DONE: Your code here. */
	/* change state to listening for activity on a socket */
	s.state = LISTENING;

	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* DONE: Your code here. */
	/* bind the socket to the server address */
	if (bind(sockfd, server, socklen)< 0){
		perror("bind");
		exit(-1);
	}

	return 0;
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* DONE: Your code here. */
	/* create a socket and return the socket file descriptor */ 
	int socketfd = socket(domain, type, protocol);
	if (socketfd < 0){
		perror("socket");
		exit(-1);
	}
	memset(&s, 0, sizeof(s));
	return socketfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* DONE: Your code here. */
	gbnhdr recv_packet, syn_ack_packet;
	int recv_len;
	int retry = 0;
	
	/* wait for SYN */
	while (retry < SYN_RETRIES) {
		recv_len = maybe_recvfrom(sockfd, &recv_packet, sizeof(recv_packet), 0, client, socklen);
		/* check checksum */
		if (recv_packet.type != SYN || checksum((uint16_t *)&recv_packet, sizeof(recv_packet)/2) != 0) {
			retry ++;			
		} else {
			break;
		}
	}
	if (retry == 5) {
		perror("Failed to receive SYN packet");
		return -1;
	}

	/* Send SYN-ACK */
	memset(&syn_ack_packet, 0, sizeof(syn_ack_packet));
	syn_ack_packet.type = SYNACK;
	int numberofwords = sizeof(syn_ack_packet)/2; /* convert bytes to words */
	syn_ack_packet.checksum = checksum((uint16_t *)&syn_ack_packet, numberofwords);
	if (maybe_sendto(sockfd, &syn_ack_packet, sizeof(syn_ack_packet), 0, client, *socklen) < 0) {
			perror("Sending SYN-ACK failed");
			return -1;
	}

	s.state = SYN_RCVD;
	return 0; 
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
