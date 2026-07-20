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

size_t open_raw_icmp_socket()
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (fd != -1)
		return fd;

	perror("Error in open_raw_icmp_socket");
	exit(EXIT_FAILURE);
}

uint64_t get_timestamp()
{
	struct timespec current;

	clock_gettime(CLOCK_MONOTONIC_RAW, &current);

	return current.tv_sec * 1000000  + current.tv_nsec;
}

int32_t checksum(void *packet)
{
	if (packet == NULL)
		return -1;

	uint16_t sum = 0;



}

void *create_icmp_echo_packet(uint16_t id, uint16_t sequence, uint64_t timestamp, size_t *payload_size)
{
	size_t packet_size = sizeof(struct icmphdr) + sizeof(uint64_t);
	*payload_size = packet_size;

	void *packet = malloc(packet_size);
	memset(packet, 0, packet_size);

	struct icmphdr *icmp_echo_request_hdr = (struct icmphdr *)packet;

	icmp_echo_request_hdr->type				= ICMP_ECHO;
	icmp_echo_request_hdr->code				= 0;
	icmp_echo_request_hdr->checksum			= 0;
	icmp_echo_request_hdr->un.echo.id		= htons(id);
	icmp_echo_request_hdr->un.echo.sequence	= htons(sequence);

	memcpy(packet + sizeof(struct icmphdr), (uint64_t *)timestamp, sizeof(uint64_t));
	return packet;
}

int main(int ac, char **av)
{
	(void)ac;
	(void)av;

	uint16_t id = (uint16_t)getpid();
	uint64_t send_timestamp = get_timestamp();
}
