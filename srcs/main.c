#include <bits/time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>

#define PERROR_AND_EXIT error_and_exit(1, __func__, "")
#define ERROR_AND_EXIT(msg) error_and_exit(0, __func__, msg)

void __attribute__((noreturn)) error_and_exit(int use_perror, const char *fn, const char *err)
{
	if (use_perror)
		perror(fn);
	else
		dprintf(2, "%s: %s\n", fn, err);
	exit(EXIT_FAILURE);
}

int open_raw_icmp_socket()
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (fd != -1)
		return fd;

	PERROR_AND_EXIT;
}

uint64_t get_timestamp()
{
	struct timespec current;

	clock_gettime(CLOCK_MONOTONIC_RAW, &current);

	return current.tv_sec * 1000000  + current.tv_nsec;
}

int32_t checksum(const uint8_t *packet, size_t length)
{
	if (packet == NULL)
		return -1;

	uint64_t sum = 0;
	size_t position = 0;
	
	while (position + 1 < length)
	{
		uint32_t word = (packet[position] << 8) | packet[position + 1];
		sum += word;
		position += 2;
	}

	if (position < length)
	{
		uint16_t word = packet[position] << 8;
		sum += word;
	}

	while (sum > 0xFFFF)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (~sum) & 0xFFFF;
}

void *create_icmp_echo_packet(uint16_t id, uint16_t sequence, uint64_t timestamp, ssize_t *payload_size, uint16_t *checksum_ret)
{
	ssize_t packet_size = sizeof(struct icmphdr) + sizeof(uint64_t);
	*payload_size = packet_size;

	void *packet = malloc(packet_size);
	if (packet == NULL)
		ERROR_AND_EXIT("Malloc failed");
	memset(packet, 0, packet_size);

	struct icmphdr *icmp_echo_request_hdr = (struct icmphdr *)packet;

	icmp_echo_request_hdr->type				= ICMP_ECHO;
	icmp_echo_request_hdr->code				= 0;
	icmp_echo_request_hdr->checksum			= 0;
	icmp_echo_request_hdr->un.echo.id		= htons(id);
	icmp_echo_request_hdr->un.echo.sequence	= htons(sequence);

	memcpy(packet + sizeof(struct icmphdr), &timestamp, sizeof(uint64_t));

	int32_t packet_checksum = checksum(packet, packet_size);
	if (packet_checksum == -1)
		ERROR_AND_EXIT("checksum received a NULL packet");

	icmp_echo_request_hdr->checksum = htons((uint16_t)packet_checksum);
	*checksum_ret = packet_checksum;
	return packet;
}

int receive_msg(int fd, uint16_t id, uint16_t sequence, uint16_t checksum)
{
	(void)checksum;
	uint8_t receive_buffer[65536] = {0};

	struct sockaddr_in sender = {0};
	socklen_t sender_length = sizeof(sender);

	ssize_t received = recvfrom(fd, receive_buffer, sizeof(receive_buffer), 0, (struct sockaddr *)&sender, &sender_length);

	if (received < 0)
		PERROR_AND_EXIT; //Need to change this to handle some kind of "normal" error such as EINTR, EAGAIN or EWOULDBLOCK
	
	if (received < 20)
		ERROR_AND_EXIT("Response too short");

	struct iphdr ip;

	memcpy(&ip, receive_buffer, sizeof(struct iphdr));

	uint16_t ip_header_length = ip.ihl * 4;
	uint16_t ip_total_length = ntohs(ip.tot_len);

	if (ip.version != 4)
		ERROR_AND_EXIT("Wrong version");
	if (ip.ihl < 5)
		ERROR_AND_EXIT("ihl too short");
	if ((ssize_t)ip_header_length > received)
		ERROR_AND_EXIT("Weird ip header length");
	if ((ssize_t)ip_total_length > received)
		ERROR_AND_EXIT("Truncated IP packet");
	if (ip_total_length < ip_header_length)
		ERROR_AND_EXIT("Invalid IP total length");

	size_t icmp_length = ip_total_length - ip_header_length;

	if (icmp_length < sizeof(struct icmphdr) + sizeof(uint64_t))
		ERROR_AND_EXIT("No icmphdr/timestamp in response");

	uint8_t *icmp_bytes = receive_buffer + ip_header_length;
	struct icmphdr icmp;

	memcpy(&icmp, icmp_bytes, sizeof(struct icmphdr));

	//Should add a check for the checksum
	if (icmp.type != ICMP_ECHOREPLY || icmp.code != 0 || ntohs(icmp.un.echo.id) != id || ntohs(icmp.un.echo.sequence) != sequence)
		return 1;

	uint8_t *payload = icmp_bytes + sizeof(struct icmphdr);
	uint64_t sent_timestamp;

	memcpy(&sent_timestamp, payload, sizeof(sent_timestamp));

	char sender_addr[64];
	inet_ntop(AF_INET, &sender.sin_addr, sender_addr, sizeof(sender_addr));

	uint64_t current_time = get_timestamp();
	printf("%zu bytes from %s: icmp_seq=%u ttl=%u time=%.2f ms\n", icmp_length, sender_addr, (unsigned)sequence, (unsigned)ip.ttl, (double)(current_time - sent_timestamp) / 1000000.0);
	return 0;
}

void poll_packet(int fd, uint16_t id, uint16_t sequence, uint16_t checksum)
{
	struct pollfd pfd;
	
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	uint64_t current_time = get_timestamp();
	uint64_t deadline = current_time + 1000000;

	while (current_time < deadline)
	{
		uint64_t remaining_ms = deadline - current_time;
		pfd.revents = 0;

		int res = poll(&pfd, 1, remaining_ms);

		if (res == 0)
			ERROR_AND_EXIT("poll Timeout"); //no need to exit here
		else if (res < 0)
			PERROR_AND_EXIT; //gonna need to change this to catch signals

		if (pfd.revents & POLLNVAL)
			ERROR_AND_EXIT("Fd is invalid or closed");
		else if (pfd.revents & POLLERR)
			ERROR_AND_EXIT("Socket error");
		else if (pfd.revents & POLLIN)
		{
			res = receive_msg(fd, id, sequence, checksum);
			if (res == 0)
				return;
		}
		current_time = get_timestamp();
	}
}
/*
int main(int ac, char **av)
{
	(void)ac;

	uint16_t id = (uint16_t)getpid();
	uint64_t send_timestamp = get_timestamp();
	struct sockaddr_in destination = {0};
	uint16_t checksum_ret;

	destination.sin_family = AF_INET;
	destination.sin_port = 0;

	int res = inet_pton(AF_INET, av[1], &destination.sin_addr);
	if (res == 0)
		ERROR_AND_EXIT("input was not a correct ipv4");
	else if (res == -1)
		PERROR_AND_EXIT;

	int fd = open_raw_icmp_socket();

	ssize_t size;
	void *packet = create_icmp_echo_packet(id, 0, send_timestamp, &size, &checksum_ret);

	ssize_t sent = sendto(fd, packet, size, 0, (const struct sockaddr *)&destination, sizeof(destination));
	if (sent == -1)
		PERROR_AND_EXIT;
	else if (sent != size)
		ERROR_AND_EXIT("incomplete send");
	else
		printf("Packet sent\n");

	poll_packet(fd, id, 0, checksum_ret);
}
*/

int main(int ac, char **av)
{
	//uint64_t prog_start_timestamp = get_timestamp();

	if (ac != 2)
		return 1;

	uint16_t pid = (uint16_t)getpid();

	struct sockaddr_in destination = {0};

	destination.sin_family = AF_INET;
	destination.sin_port = 0;

	int res = inet_pton(AF_INET, av[1], &destination.sin_addr);
	if (res == 0)
		ERROR_AND_EXIT("Name or service not known"); //should add the av[1] to the msg
	else if (res == -1)
		PERROR_AND_EXIT;

	int fd = open_raw_icmp_socket();

	ssize_t size;
	uint16_t checksum;

	printf("PING %s (%s) %ld(%ld) bytes of data.\n", av[1], av[1], sizeof(uint64_t), sizeof(struct icmphdr) + sizeof(uint64_t) + sizeof(struct iphdr));

	for (int i = 0; i != 5; i++)
	{
		uint64_t send_timestamp = get_timestamp();
		void *packet = create_icmp_echo_packet(pid, i, send_timestamp, &size, &checksum);
		ssize_t sent = sendto(fd, packet, size, 0, (const struct sockaddr *)&destination, sizeof(destination));
		if (sent == -1)
			PERROR_AND_EXIT;
		else if (sent != size)
			ERROR_AND_EXIT("incomplete send");

		poll_packet(fd, pid, i, checksum);
		sleep(1);
	}

	printf("--- %s ping statistics ---", av[1]);
}
