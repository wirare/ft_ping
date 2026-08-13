/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eliot <eliot@42angouleme.fr>               +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/12 11:38:58 by eliot             #+#    #+#             */
/*   Updated: 2026/08/12 17:00:29 by eliot            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <bits/time.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
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
#include <ping.h>
#include <netdb.h>

#define PERROR_AND_EXIT error_and_exit(1, __func__, "")
#define ERROR_AND_EXIT(msg) error_and_exit(0, __func__, msg)

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t print_requested = 0;

t_data	g_statistics;

void __attribute__((noreturn)) quit(int ret)
{
	if (g_statistics.packet_is_freed == 0)
		free(g_statistics.packet);
	free(g_statistics.addr);
	free(g_statistics.rcv_times);
	exit(ret);
}

void __attribute__((noreturn)) error_and_exit(int use_perror, const char *fn, const char *err)
{
	if (use_perror)
		perror(fn);
	else
		dprintf(2, "%s: %s\n", fn, err);
	quit(EXIT_FAILURE);
}

int open_raw_icmp_socket()
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (fd != -1)
		return fd;

	PERROR_AND_EXIT;
}

uint64_t get_timestamp(void)
{
	struct timespec current;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &current) == -1)
		PERROR_AND_EXIT;

	return ((uint64_t)current.tv_sec * 1000000000ULL) + (uint64_t)current.tv_nsec;
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

void *create_icmp_echo_packet(uint16_t id, uint16_t sequence, uint64_t timestamp, size_t *packet_size)
{
	uint8_t *packet = calloc(1, ICMP_PACKET_SIZE);
	if (packet == NULL)
		ERROR_AND_EXIT("allocation failed");

	struct icmphdr *icmp_echo_request_hdr = (struct icmphdr *)packet;

	icmp_echo_request_hdr->type				= ICMP_ECHO;
	icmp_echo_request_hdr->code				= 0;
	icmp_echo_request_hdr->checksum			= 0;
	icmp_echo_request_hdr->un.echo.id		= htons(id);
	icmp_echo_request_hdr->un.echo.sequence	= htons(sequence);

	memcpy(packet + sizeof(struct icmphdr), &timestamp, sizeof(timestamp));

	size_t i = sizeof(timestamp);
	while (i < ICMP_PAYLOAD_SIZE)
	{
		packet[sizeof(struct icmphdr) + i] = (uint8_t)i;
		i++;
	}

	int32_t packet_checksum = checksum(packet, ICMP_PACKET_SIZE);
	if (packet_checksum == -1)
		ERROR_AND_EXIT("checksum received a NULL packet");

	icmp_echo_request_hdr->checksum = htons((uint16_t)packet_checksum);
	*packet_size = ICMP_PACKET_SIZE;
	return packet;
}

int receive_msg(int fd, uint16_t id)
{
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
	if (icmp.type != ICMP_ECHOREPLY || icmp.code != 0 || ntohs(icmp.un.echo.id) != id)
		return 1;

	uint8_t *payload = icmp_bytes + sizeof(struct icmphdr);
	uint64_t sent_timestamp;

	memcpy(&sent_timestamp, payload, sizeof(sent_timestamp));

	inet_ntop(AF_INET, &sender.sin_addr, g_statistics.sender_addr, sizeof(g_statistics.sender_addr));

	uint64_t current_time = get_timestamp();
	g_statistics.timing = (double)(current_time - sent_timestamp) / 1000000.0;
	g_statistics.received = 1;
	g_statistics.icmp_length = icmp_length;
	g_statistics.ttl = ip.ttl;
	g_statistics.sequence = ntohs(icmp.un.echo.sequence);
	return 0;
}

 double compute_mdev(double *list, size_t size, double average)
{
	double mdev = 0;

	for (size_t i = 0; i != size; i++)
	{
		double tmp = list[i] - average;
		mdev += tmp * tmp;
	}

	mdev /= size;

	return sqrt(mdev);
}

void print_statistic(int opt)
{
	double min = INT_MAX;
	double max = INT_MIN;
	double avg = 0;
	size_t size = g_statistics.rcv_times_idx;

	for (size_t i = 0; i != size; i++)
	{
		double current = g_statistics.rcv_times[i];

		if (current < min)
			min = current;
		
		if (current > max)
			max = current;

		avg += current;
	}

	avg /= size;
	
	size_t loss = g_statistics.loss;
	size_t total_packet_number = g_statistics.rcv_times_idx;
	
	if (opt == 0)
	{
		double mdev = compute_mdev(g_statistics.rcv_times, size, avg);
		printf("--- %s ping statistics ---\n", g_statistics.addr);
		printf("%zu packets transmitted, %zu received, %.01f%% packets loss, time %lu ms\n", total_packet_number, total_packet_number - loss, loss / (double)total_packet_number, (get_timestamp() - g_statistics.prog_start_timestamp) / 1000000);
		printf("rtt min/avg/max/mdev = %.03f/%.03f/%.03f/%.03f ms\n", min, avg, max, mdev);
		return;
	}
	if (opt == 1)
	{
		printf("%zu/%zu packets, %.01f%% loss, min/avg/ewma/max = %.03f/%.03f/%.03f/%.03f ms\n", total_packet_number - loss, total_packet_number, loss / (double)total_packet_number, min, avg, g_statistics.ewma, max);
		return;
	}
}

void handle_signals(int signo)
{
	if (signo == SIGQUIT)
		print_requested = 1;
	else
		stop_requested = 1;
}

void setup_signals()
{
	struct sigaction sa = {0};

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = handle_signals;

	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
}

void check_sig()
{
	if (print_requested)
	{
		printf("\n");
		print_statistic(1);
		print_requested = 0;
	}
	else if (stop_requested)
	{
		printf("\n");
		print_statistic(0);
		quit(EXIT_SUCCESS);
	}
}

int milliseconds_until(uint64_t deadline)
{
	uint64_t now;
	uint64_t remaining;
	uint64_t milliseconds;

	now = get_timestamp();
	if (now >= deadline)
		return 0;

	remaining = deadline - now;
	milliseconds = remaining / NS_PER_MILLISECOND;
	if (remaining % NS_PER_SECOND != 0)
		milliseconds++;
	if (milliseconds > INT_MAX)
		return INT_MAX;
	return (int)milliseconds;
}

int resolve_ipv4(const char *host, struct sockaddr_in *destination, char numeric_addr[INET_ADDRSTRLEN])
{
	struct addrinfo hints;
	struct addrinfo *result;
	int status;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;

	status = getaddrinfo(host, NULL, &hints, &result);
	if (status != 0)
	{
		fprintf(stderr, "ft_ping: %s: %s\n", host, gai_strerror(status));
		return -1;
	}

	if (result == NULL || result->ai_addrlen < sizeof(struct sockaddr_in))
	{
		fprintf(stderr, "ft_ping: %s: no IPv4 address found\n", host);
		freeaddrinfo(result);
		return -1;
	}

	memcpy(destination, result->ai_addr, sizeof(*destination));

	if (inet_ntop(AF_INET, &destination->sin_addr, numeric_addr, INET_ADDRSTRLEN) == NULL)
	{
		perror("ft_ping: inet_ntop");
		freeaddrinfo(result);
		return -1;
	}

	freeaddrinfo(result);
	return 0;
}

static void	record_reply(void)
{
	double	*new_times;
	size_t	new_size;

	printf(
		"%zu bytes from %s: icmp_seq=%u ttl=%u time=%.3f ms\n",
		g_statistics.icmp_length,
		g_statistics.sender_addr,
		g_statistics.sequence,
		g_statistics.ttl,
		g_statistics.timing
	);

	if (g_statistics.rcv_times_idx == g_statistics.rcv_times_size)
	{
		new_size = g_statistics.rcv_times_size * 2;
		new_times = realloc(
			g_statistics.rcv_times,
			new_size * sizeof(*new_times)
		);
		if (new_times == NULL)
			ERROR_AND_EXIT("reallocation failed");
		g_statistics.rcv_times = new_times;
		g_statistics.rcv_times_size = new_size;
	}

	if (g_statistics.ewma < 0.0)
		g_statistics.ewma = g_statistics.timing;
	else
	{
		g_statistics.ewma =
			(7.0 / 8.0) * g_statistics.ewma
			+ (1.0 / 8.0) * g_statistics.timing;
	}

	g_statistics.rcv_times[g_statistics.rcv_times_idx]
		= g_statistics.timing;
	g_statistics.rcv_times_idx++;
}

void send_echo_request(int fd, const struct sockaddr_in *destination, uint16_t id, uint16_t sequence)
{
	size_t packet_size;
	ssize_t sent;

	g_statistics.packet = create_icmp_echo_packet(id, sequence, get_timestamp(), &packet_size);
	g_statistics.packet_is_freed = 0;

	while (1)
	{
		sent = sendto(fd, g_statistics.packet, packet_size, 0, (const struct sockaddr *)destination, sizeof(*destination));
		if (sent >= 0)
			break;
		if (errno != EINTR)
			PERROR_AND_EXIT;
		check_sig();
	}
	if ((size_t)sent != packet_size)
		ERROR_AND_EXIT("incomplete send");

	free(g_statistics.packet);
	g_statistics.packet = NULL;
	g_statistics.packet_is_freed = 1;
	g_statistics.transmitted++;
}

static void	run_ping(int fd, const struct sockaddr_in *destination, uint16_t id)
{
	struct pollfd pfd;
	uint64_t next_send;
	uint64_t now;
	uint16_t sequence;
	int	status;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	sequence = 0;
	next_send = get_timestamp();

	while (1)
	{
		check_sig();
		now = get_timestamp();

		if (now >= next_send)
		{
			send_echo_request(fd, destination, id, sequence);
			sequence++;

			next_send += PING_INTERVAL_NS;
			now = get_timestamp();

			if (next_send <= now)
				next_send = now + PING_INTERVAL_NS;
		}

		pfd.revents = 0;
		status = poll(&pfd, 1, milliseconds_until(next_send));

		if (status == 0)
			continue;

		if (status < 0)
		{
			if (errno == EINTR)
			{
				check_sig();
				continue;
			}

			PERROR_AND_EXIT;
		}

		if (pfd.revents & POLLNVAL)
			ERROR_AND_EXIT("invalid socket descriptor");

		if (pfd.revents & POLLIN)
		{
			status = receive_msg(fd, id);
			if (status == 0)
				record_reply();
		}

		if (pfd.revents & (POLLERR | POLLHUP))
			ERROR_AND_EXIT("socket polling error");
	}
}

int main(int ac, char **av)
{
	t_arguments arguments = 
	{
		.opt = OPT_NONE,
		.host = NULL
	};

	argp_parse(&parser, ac, av, 0, NULL, &arguments);

	g_statistics.opt = arguments.opt;
	g_statistics.prog_start_timestamp = get_timestamp();

	setup_signals();

	uint16_t pid = (uint16_t)getpid();

	struct sockaddr_in destination;
	char numeric_addr[INET_ADDRSTRLEN];

	memset(&destination, 0, sizeof(destination));

	if (resolve_ipv4(arguments.host, &destination, numeric_addr) != 0)
		return EXIT_FAILURE;

	int fd = open_raw_icmp_socket();

	g_statistics.rcv_times = malloc(32 * sizeof(double));
	g_statistics.rcv_times_size = 32;
	g_statistics.rcv_times_idx = 0;
	g_statistics.ewma = -1;

	size_t host_len = strlen(arguments.host);

	g_statistics.addr = malloc(host_len * sizeof(char) + 1);
	g_statistics.addr[host_len] = '\0';
	memcpy(g_statistics.addr, arguments.host, host_len);

	printf("PING %s (%s): %u data bytes\n", arguments.host, numeric_addr, ICMP_PAYLOAD_SIZE);

	run_ping(fd, &destination, pid);
}
