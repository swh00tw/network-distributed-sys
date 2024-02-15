#include "gbn.h"

state_t s = {CLOSED};

/* sender global variables */
struct sockaddr *recv_addr;
socklen_t recv_addrlen;
uint8_t base = 0;
uint8_t nextseqnum = 0;
uint8_t window_size = 4;
gbnhdr *pkts[N];
int recv_sockfd;

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

void sigalrm_resend_packet_handler(int signum) {
	alarm(TIMEOUT);
	int i;
	for (i = base; i < nextseqnum; i++) {
		ssize_t bytes_sent = maybe_sendto(recv_sockfd, pkts[i], sizeof(gbnhdr), 0, recv_addr, recv_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(pkts[i]);
			exit(-1);
		}
		printf("resend data seqnum: %d\n", pkts[i]->seqnum);
	}
}

void sigalrm_resend_fin_handler(int signum) {
	alarm(TIMEOUT);
	gbnhdr *fin = make_pkt(FIN, base, NULL, 0);
	ssize_t bytes_sent = sendto(recv_sockfd, fin, sizeof(gbnhdr), 0, recv_addr, recv_addrlen);
	if (bytes_sent == -1){
		perror("sendto failed");
		free(fin);
		exit(-1);
	}
	printf("resend FIN\n");
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
 1. congestion control
*/
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	recv_sockfd = sockfd;
	signal(SIGALRM, sigalrm_resend_packet_handler);

	/* calculate how many packets to be sent */
	size_t packets_num = len / DATALEN;
	if (len % DATALEN != 0){
		packets_num++;
	}

	printf("Finish initialize %d packets.\nStart sending...\n", packets_num);
	while (1) {
		/* send packets if available */
		int cnt = 0;
		while (nextseqnum < base + window_size && len > 0) {
			size_t chunk_size = len > DATALEN ? DATALEN : len;
			pkts[nextseqnum] = make_pkt(DATA, nextseqnum, buf, chunk_size);
			ssize_t bytes_sent = maybe_sendto(sockfd, pkts[nextseqnum], sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
			if (bytes_sent == -1){
				free(pkts[nextseqnum]);
				return -1;
			}
			printf("send data seqnum: %d\n", pkts[nextseqnum]->seqnum);

			if (base == nextseqnum) {
				alarm(TIMEOUT);
			}

			nextseqnum++;
			cnt++;
			len -= chunk_size;
			buf += chunk_size;
		}
		/* receive ack */
		gbnhdr *ack = malloc(sizeof(gbnhdr));
		memset(ack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = maybe_recvfrom(sockfd, ack, sizeof(gbnhdr), 0, NULL, NULL);

		if (bytes_recv == -1 || ack->type != DATAACK || is_corrupted(ack)){
			perror("DATAACK packet corrupted\n");
		} 
		else if (ack->seqnum < base) {
			printf("duplicated ack: %d\n", ack->seqnum);
		}
		else {
			printf("recv ack seqnum: %d\n", ack->seqnum);
			free(pkts[ack->seqnum]);
			base = ack->seqnum + 1;

			if (base == nextseqnum) {
				alarm(0);
			} else {
				alarm(TIMEOUT);
			}
		}

		free(ack);
		if (base == packets_num) {
			break;
		}
	}

	/* send FIN after finish */
	signal(SIGALRM, sigalrm_resend_fin_handler);
	while (1) {
		gbnhdr *fin = make_pkt(FIN, base, NULL, 0);
		ssize_t bytes_sent = sendto(sockfd, fin, sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(fin);
			return -1;
		}

		/* set timer */
		alarm(TIMEOUT);

		/* receive FINACK */
		gbnhdr *finack = malloc(sizeof(gbnhdr));
		memset(finack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = recvfrom(sockfd, finack, sizeof(gbnhdr), 0, NULL, NULL);
		if (bytes_recv == -1 || finack->type != FINACK || is_corrupted(finack)){
			perror("FINACK packet corrupted\n");
		} else {
			printf("recv FINACK\n");
			break;
		}
	}

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	gbnhdr *data = malloc(sizeof(gbnhdr));
	memset(data, 0, sizeof(gbnhdr));

	while (1) {
		ssize_t bytes_recv = maybe_recvfrom(sockfd, data, sizeof(gbnhdr), 0, NULL, NULL);
		if (bytes_recv == -1) {
			perror("recvfrom failed");
			free(data);
			return -1;
		}

		if (is_corrupted(data)) {
			perror("DATA packet corrupted\n");
			continue;
		}

		if (data->type == FIN) {
			free(data);
			/* send finack */
			gbnhdr *finack = make_pkt(FINACK, 0, NULL, 0);
			ssize_t bytes_sent = sendto(sockfd, finack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
			if (bytes_sent == -1){
				perror("sendto failed");
				free(finack);
				return -1;
			}
			free(finack);
			return 0;
		}
		if (data->type != DATA) {
			perror("Received packet is not DATA\n");
			continue;
		}

		int should_deliver = 1;
		uint8_t ack_seqnum = data->seqnum;
		if (!check_seq_num(expectedseqnum, data)) {
			/* send duplicated ack */
			ack_seqnum = expectedseqnum - 1;
			should_deliver = 0;
		}

		printf("recv data seqnum: %d\n", data->seqnum);

		gbnhdr *ack = make_pkt(DATAACK, ack_seqnum, NULL, 0);
		ssize_t bytes_sent = maybe_sendto(sockfd, ack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(data);
			free(ack);
			return -1;
		}

		if (should_deliver) {
			/* write data to buf */
			printf("deliver data seq: %d\n", data->seqnum);
			memcpy(buf, data->data, len);
			expectedseqnum++;
			break;
		}
		free(ack);
	}

	ssize_t bytes_len = strlen(data->data);
	free(data);

	return bytes_len;
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
	if (rand() > 0.1*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < 0.1*RAND_MAX){
			printf("Maybe Recv: Packet corrupted\n");
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
	printf("Maybe Recv: Packet lost\n");
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > 0.1*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < 0.1*RAND_MAX){
            printf("Maybe Send: Packet corrupted\n");
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
    else {
			printf("Maybe Send: Packet lost\n");
      return(len);
		}  /* Simulate a success */
}
