#include "gbn.h"

state_t s = {CLOSED};
struct sockaddr *recv_addr;
socklen_t recv_addrlen;
struct sockaddr *send_addr;
socklen_t send_addrlen;

int seq_num = 0;

gbnhdr* make_pkt(uint8_t type, uint8_t seqnum, const void *buf, size_t datalen) {
	gbnhdr *pkt = malloc(sizeof(gbnhdr));
	memset(pkt, 0, sizeof(gbnhdr));
	pkt->type = type;
	pkt->seqnum = seqnum;
	if (type == DATA) {
		memcpy(pkt->data, buf, datalen);
	}
	pkt->checksum = checksum((uint16_t *)pkt, sizeof(gbnhdr)/2);
	return pkt;
}

int is_corrupted(gbnhdr *pkt) {
	uint16_t checksum_recv = pkt->checksum;
	pkt->checksum = 0;
	if (checksum_recv != checksum((uint16_t *)pkt, sizeof(gbnhdr)/2)) {
		return 1;
	}
	return 0;
}

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
		gbnhdr *data = make_pkt(DATA, seq_num, buf, chunk_size);
		ssize_t bytes_sent = sendto(sockfd, data, sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(data);
			return -1;
		}
		
		/* receive ack */
		gbnhdr *ack = malloc(sizeof(gbnhdr));
		memset(ack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = recvfrom(sockfd, ack, sizeof(gbnhdr), 0, NULL, NULL);
		if (bytes_recv == -1){
			perror("recvfrom failed");
			free(data);
			return -1;
		}

		if (ack->type != DATAACK || is_corrupted(ack)){
			perror("DATAACK packet corrupted\n");
			free(data);
			return -1;
		}

		free(data);
		free(ack);

		len -= chunk_size;
		buf += chunk_size;
		chunk_size = len > DATALEN ? DATALEN : len;
	}

	/* send FIN after finish */
	gbnhdr *fin = make_pkt(FIN, seq_num, NULL, 0);
	ssize_t bytes_sent = sendto(sockfd, fin, sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		free(fin);
		return -1;
	}

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	gbnhdr *data = malloc(sizeof(gbnhdr));
	memset(data, 0, sizeof(gbnhdr));

	ssize_t bytes_recv = recvfrom(sockfd, data, sizeof(gbnhdr), 0, NULL, NULL);
	if (bytes_recv == -1){
		perror("recvfrom failed");
		free(data);
		return -1;
	}

	if (is_corrupted(data)) {
		perror("DATA packet corrupted\n");
		free(data);
		return -1;
	}

	if (data->type == FIN) {
		free(data);
		return 0;
	}

	if (data->type != DATA) {
		perror("DATA packet corrupted\n");
		free(data);
		return -1;
	}

	gbnhdr *ack = make_pkt(DATAACK, data->seqnum, NULL, 0);
	ssize_t bytes_sent = sendto(sockfd, ack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		free(data);
		free(ack);
		return -1;
	}
	/* write data to buf */
	memcpy(buf, data->data, len);

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
	gbnhdr *syn = make_pkt(SYN, 0, NULL, 0);
	
	ssize_t bytes_sent = sendto(sockfd, syn, sizeof(gbnhdr), 0, server, socklen);
	s.state = SYN_SENT;
	
	/* Receive SYNACK */
	gbnhdr *synack = malloc(sizeof(gbnhdr));
	memset(synack, 0, sizeof(gbnhdr));

	/* Receive SYNACK packet */
	ssize_t bytes_recv = recvfrom(sockfd, synack, sizeof(gbnhdr), 0, NULL, NULL);
	
	/* Check if SYNACK packet is corrupted */
	if (synack->type != SYNACK || is_corrupted(synack)){
		free(syn);
		free(synack);
		perror("SYNACK packet corrupted\n");
		return -1;
	}

	/* Free memory */
	free(syn);
	free(synack);

	/* Set Receiver address */
	recv_addr = (struct sockaddr *) server;
	recv_addrlen = socklen;
	s.state = ESTABLISHED;
	seq_num = 0;

	
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
	if (syn->type != SYN || is_corrupted(syn)){
		free(syn);
		perror("SYN packet corrupted\n");
		return -1;
	}
	s.state = SYN_RCVD;

	/* Free memory */
	free(syn);
	

	/* Send SYNACK */
	gbnhdr *synack = make_pkt(SYNACK, 0, NULL, 0);	
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
