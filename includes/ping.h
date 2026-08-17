#pragma once

#include <stddef.h>
#include <stdint.h>
#include <argp.h>

typedef enum
{
	OPT_NONE = 0,
	OPT_VERBOSE = 1 << 0,
}	e_opt;

typedef struct
{
	e_opt opt;

	char *addr;

	void *packet;
	char packet_is_freed;

	size_t icmp_length;
	char sender_addr[64];
	unsigned int ttl;
	double timing;

	uint16_t sequence;
	size_t transmitted;

	uint64_t prog_start_timestamp;

	size_t received_unique;
	size_t duplicates;

	size_t rtt_count;
	double rtt_min;
	double rtt_max;
	double rtt_sum;
	double rtt_sum_squared;

	char is_duplicate;

	uint8_t sequence_state[UINT16_MAX + 1U];

}	t_data;

typedef struct
{
	e_opt		opt;
	const char	*host;
}	t_arguments;

extern const struct argp parser;

#define ICMP_PAYLOAD_SIZE 56U
#define ICMP_PACKET_SIZE (sizeof(struct icmphdr) + ICMP_PAYLOAD_SIZE)

#define NS_PER_SECOND		1000000000ULL
#define NS_PER_MILLISECOND	1000000ULL
#define PING_INTERVAL_NS	NS_PER_SECOND
