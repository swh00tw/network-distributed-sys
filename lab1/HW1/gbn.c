#include "gbn.h"
#define min(a, b) ((a) < (b) ? (a) : (b))
#define MAX_SEQ 256

state_t s = {CLOSED};

/* Sender global variables */
struct sockaddr *recv_addr;
socklen_t recv_addrlen;
uint16_t base = 0;
uint16_t nextseqnum = 0;
uint8_t cycle_num = 0;

uint16_t window_size = 1;
uint16_t max_window_size = 256;
gbnhdr *pkts[N];
int recv_sockfd;

/* Receiver global variables */
struct sockaddr *send_addr;
socklen_t send_addrlen;
uint8_t expectedseqnum = 0;

uint8_t mod(uint8_t a, uint8_t b) {
	return ((a % b) + b) % b;
}

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
	
	/* Decrease window size */
	if (window_size > 1) {
		window_size /= 2;
	}

	alarm(TIMEOUT);

	/* Resend all packets that has been sent in the sliding window */
	int i;
	for (i = base; i < nextseqnum; i++) {
		ssize_t bytes_sent = maybe_sendto(recv_sockfd, pkts[i], sizeof(gbnhdr), 0, recv_addr, recv_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(pkts[i]);
			exit(-1);
		}
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

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/*
	 * This function is used to send data in the buf to the receiver. If the data is 
	 * larger than DATALEN, it will be split into multiple packets.
	 * 
	 * The sender will send the packets within the sliding window to the receiver, and 
	 * wait for the receiver to send back the ack.
	 * 
	 * A timer for oldest in-flight pkt will be setup, and if the timer expires,
	 * the sender will resend the pkts that are not yet acked.
	 */

	/* Initialize global variables */
	base = 0;
	nextseqnum = 0;
	cycle_num = 0;
	recv_sockfd = sockfd;

	/* Set SIGALRM signal handler for resending packet*/
	signal(SIGALRM, sigalrm_resend_packet_handler);

	/* Initialize packet buffer */
	int i;
	for (i = 0; i < N; i++) {
		if (pkts[i] != NULL) {
			free(pkts[i]);
			pkts[i] = NULL;
		}
	}

	/* Calculate how many packets to be sent */
	size_t packets_num = len / DATALEN;
	if (len % DATALEN != 0){
		packets_num++;
	}

	/* Set the upper bound fo window size */
	max_window_size = min(max_window_size, packets_num);

	while (1) {
		/* Send packets in the sliding window */
		while (nextseqnum < base + window_size && len > 0) {
			size_t chunk_size = len > DATALEN ? DATALEN : len;
			pkts[nextseqnum] = make_pkt(DATA, mod(nextseqnum, MAX_SEQ), buf, chunk_size);
			ssize_t bytes_sent = maybe_sendto(sockfd, pkts[nextseqnum], sizeof(gbnhdr), flags, recv_addr, recv_addrlen);
			if (bytes_sent == -1){
				free(pkts[nextseqnum]);
				return -1;
			}

			/* Set timer if this packet is the oldest in-flight packet*/
			if (base == nextseqnum) {
				alarm(TIMEOUT);
			}

			nextseqnum++;
			len -= chunk_size;
			buf += chunk_size;
		}

		/* Receive ack */
		gbnhdr *ack = malloc(sizeof(gbnhdr));
		memset(ack, 0, sizeof(gbnhdr));
		ssize_t bytes_recv = maybe_recvfrom(sockfd, ack, sizeof(gbnhdr), 0, NULL, NULL);

		if (bytes_recv == -1) {
			perror("recvfrom failed");
			free(ack);
			return -1;
		}

		if (ack->type != DATAACK || is_corrupted(ack)){
			/* Ignore if the ack is corrupted */
			perror("DATAACK packet corrupted\n");
		} else if (mod((ack->seqnum - mod(base, MAX_SEQ)), MAX_SEQ) < (nextseqnum - base)) {
			/* non duplicate ack*/
			/*
			 * Why do we need to use mod(base, MAX_SEQ) here?
			 * Because ack->seqnum is bounded by [0, 255], and base can be larger than MAX_SEQ.
			 * We need to calculate the distance between base and ack->seqnum in a circular way to
			 * determine if the ack is a duplicate ack.
			 * 
			 * What is cycle_num used for?
			 * The maximum amount of packets can be N = 1024, but the sequence number is bounded [0, 255].
			 * So we need to use cycle_num to keep track of the number of cycles of the sequence number.
			*/

			if (mod(ack->seqnum + 1, MAX_SEQ) < mod(base, MAX_SEQ)) {
				cycle_num++;
			}
			
			/* The ack->seqnum is the highest in-order seqnum received by the receiver.
			 * In this case, we can move the window forward by updating the base.
			*/
			base = (uint16_t) cycle_num * MAX_SEQ + mod(ack->seqnum + 1, MAX_SEQ);

			/* Enlarge the window size if the ack successfully received */
			window_size = window_size*2 > max_window_size ? window_size : window_size*2;

			if (base == nextseqnum) {
				/* All packets are acked */
				alarm(0);
			} else {
				/* Reset timer for the oldest in-flight packet */
				alarm(TIMEOUT);
			}
		}

		free(ack);

		/* Check if all packets are sent */
		if (base == packets_num) {
			break;
		}
	}

	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* This function is used to receive data from the sender.
	 * The receiver will keep listening the packets from the sender, and send back the ack to the sender.
	 * It will keep receiving the packets until it receives the packet with expected seqnum.
	 * 
	 * If the packet is corrupted, the receiver will ignore the packet.
	 * If the packet is in-order, the receiver will write the data to the buf and update the expected seqnum.
	 * If the packet is not in-order, the receiver will discard the packet and send back the duplicated ack.
	 * If the receiver receives the FIN packet, it will send back the FINACK.
	*/

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
			/* Ignore if the packet is corrupted */
			perror("DATA packet corrupted\n");
			continue;
		}

		if (data->type == FIN) {
			free(data);

			/* Send finack */
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

		/* If the seqnum is not in-order, discard the packet and send duplicated ack. */
		if (!check_seq_num(expectedseqnum, data)) {
			ack_seqnum = expectedseqnum - 1;
			should_deliver = 0;
		}

		/* Send ack to the sender */
		gbnhdr *ack = make_pkt(DATAACK, ack_seqnum, NULL, 0);
		ssize_t bytes_sent = maybe_sendto(sockfd, ack, sizeof(gbnhdr), flags, send_addr, send_addrlen);
		if (bytes_sent == -1){
			perror("sendto failed");
			free(data);
			free(ack);
			return -1;
		}

		free(ack);

		/* If the seqnum is in-order, write data to buf and update the expected seqnum. */
		if (should_deliver) {
			memcpy(buf, data->data, len);
			expectedseqnum++;
			break;
		}
	}

	/* Trim the padding NULL at the end of the packet */
	ssize_t bytes_len = strlen(data->data);
	free(data);

	return bytes_len;
}

int gbn_close(int sockfd){

	/* This function is used to close the connection between the sender and the receiver.
	 *
	 * The sender will call this function after sending all data. It will send the FIN packet 
	 * to the receiver, and wait for the FINACK from the receiver. After receiving the FINACK,
	 * it will close the connection.
	 * 
	 * If the receiver receives the FIN, it will send back the FINACK to the sender, and 
	 * call this function to close the connection.
	*/
	
	/* Only send FIN in the sender */
	if (s.state == ESTABLISHED) {
		signal(SIGALRM, sigalrm_resend_fin_handler);
		while (1) {
			gbnhdr *fin = make_pkt(FIN, 0, NULL, 0);
			ssize_t bytes_sent = sendto(sockfd, fin, sizeof(gbnhdr), 0, recv_addr, recv_addrlen);
			if (bytes_sent == -1){
				perror("sendto failed");
				free(fin);
				return -1;
			}
			s.state = FIN_SENT;

			/* Set timer */
			alarm(TIMEOUT);

			/* Receive FINACK */
			gbnhdr *finack = malloc(sizeof(gbnhdr));
			memset(finack, 0, sizeof(gbnhdr));
			ssize_t bytes_recv = recvfrom(sockfd, finack, sizeof(gbnhdr), 0, NULL, NULL);
			if (bytes_recv == -1 || finack->type != FINACK || is_corrupted(finack)){
				perror("FINACK packet corrupted\n");
			} else {
				free(finack);
				free(fin);
				s.state = FIN_RCVD;
				break;
			}
		}
	}

	s.state = CLOSED;
	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* This function is called by sender and used to establish a connection between 
	 * the sender and the receiver.
	 * The sender will send the SYN packet to the receiver, and wait for the SYNACK from 
	 * the receiver.
	*/

	gbnhdr *syn = make_pkt(SYN, 0, NULL, 0);
	ssize_t bytes_sent = sendto(sockfd, syn, sizeof(gbnhdr), 0, server, socklen);
	s.state = SYN_SENT;
	
	/* Receive SYNACK */
	gbnhdr *synack = malloc(sizeof(gbnhdr));
	memset(synack, 0, sizeof(gbnhdr));
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
	
	return 0;
}

int gbn_listen(int sockfd, int backlog){
	s.state = LISTENING;
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* This function is called by the receiver and used to accept the connection from the sender.
	 * The receiver will wait for the SYN packet from the sender, and send back the SYNACK to 
	 * the sender.
	*/

	/* Receive SYN */
	gbnhdr *syn = malloc(sizeof(gbnhdr));
	memset(syn, 0, sizeof(gbnhdr));
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
    else {
      return(len);
		}  /* Simulate a success */
}
