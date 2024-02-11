#include "gbn.h"

state_t s = {CLOSED};

/* sender global variables */
struct sockaddr *recv_addr;
socklen_t recv_addrlen;
uint8_t base = 0;
uint8_t nextseqnum = 0;
uint8_t window_size = 4;

/* receiver global variables */
struct sockaddr *send_addr;
socklen_t send_addrlen;
uint8_t expectedseqnum = 0;

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

int check_seq_num(uint8_t expected_seqnum, gbnhdr *pkt) {
	if (pkt->seqnum != expected_seqnum) {
		return 0;
	}
	return 1;
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
 1. go back N handle error
 2. congestion control
 3. solve the NULL problem
*/
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	/* calculate how many packets to be sent */
	printf("Initialize sending...\n");
	size_t packets_num = len / DATALEN;
	if (len % DATALEN != 0){
		packets_num++;
	}
	/* store pkts */
	gbnhdr *pkts[packets_num];

	printf("Finish initialize %d packets.\nStart sending...\n", packets_num);
	while (1) {
		/* send packets if available */
		int cnt = 0;
		while (nextseqnum < base + window_size && len > 0) {
			size_t chunk_size = len > DATALEN ? DATALEN : len;
			pkts[nextseqnum] = make_pkt(DATA, nextseqnum, buf, chunk_size);
			ssize_t bytes_sent = sendto(sockfd, pkts[nextseqnum], sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
			if (bytes_sent == -1){
				perror("sendto failed");
				free(pkts[nextseqnum]);
				return -1;
			}
			printf("send data seqnum: %d\n", pkts[nextseqnum]->seqnum);
			nextseqnum++;
			cnt++;
			len -= chunk_size;
			buf += chunk_size;
		}
		printf("Finish sending %d packets.\n", cnt);
		/* receive ack */
		gbnhdr *ack = malloc(sizeof(gbnhdr));
		memset(ack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = recvfrom(sockfd, ack, sizeof(gbnhdr), 0, NULL, NULL);

		if (bytes_recv == -1 || ack->type != DATAACK || is_corrupted(ack) || !check_seq_num(base, ack)){
			perror("DATAACK packet corrupted\n");
		} else {
			free(pkts[ack->seqnum]);
			base++;
		}

		free(ack);
		if (base == packets_num) {
			break;
		}
	}

	/* send FIN after finish */
	gbnhdr *fin = make_pkt(FIN, base, NULL, 0);
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
	if (bytes_recv == -1 || is_corrupted(data)) {
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

	uint8_t ack_seqnum = data->seqnum;
	int should_deliver = 1;
	if (!check_seq_num(expectedseqnum, data)) {
		/* send duplicated ack */
		ack_seqnum = expectedseqnum - 1;
		should_deliver = 0;
	}

	printf("recv data seqnum: %d\n", data->seqnum);

	gbnhdr *ack = make_pkt(DATAACK, ack_seqnum, NULL, 0);
	ssize_t bytes_sent = sendto(sockfd, ack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		free(data);
		free(ack);
		return -1;
	}

	if (should_deliver) {
		/* write data to buf */
		memcpy(buf, data->data, len);
		expectedseqnum++;
	}
	

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
	base = 0;
	nextseqnum = 0;

	
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
	expectedseqnum = 0;

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
