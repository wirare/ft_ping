#include <argp.h>
#include <ping.h>

static const struct argp_option options[] = 
{
	{
		.name = "verbose",
		.key = 'v',
		.arg = NULL,
		.flags = 0,
		.doc = "verbose output"
	},
	{0}
};

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	t_arguments *arguments;

	arguments = state->input;
	switch (key)
	{
		case 'v':
			{
				arguments->opt |= OPT_VERBOSE;
				break;
			}

		case ARGP_KEY_ARG:
			{
				if (arguments->host != NULL)
					argp_error(state, "too many host operands");
				arguments->host = arg;
				break;
			}

		case ARGP_KEY_END:
			{
				if (arguments->host == NULL)
					argp_error(state, "missing host operand");
				break;
			}

		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp parser = {
	.options = options,
	.parser = parse_option,
	.args_doc = "HOST",
	.doc = "Send ICMP ECHO_REQUEST packets to network hosts."
};
