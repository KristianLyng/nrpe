/*
 * check_nrpe.c - NRPE Plugin For Nagios
 * Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)
 * Copyright (c) 2011 Kristian Lyngstol <kristian@bohemians.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*
 * XXX: I've inserted the GPLv2+ header as it was missing and only "GPL"
 * XXX: was mentioned. This was chosen as the GPLv2+-header is present
 * XXX: elsewhere in nrpe. It is presumed to apply to the existing code,
 * XXX: and it applies to my contributions as well.
 * XXX:    - Kristian Lyngstol, March, 2011
 *
 * This plugin will attempt to connect to the NRPE daemon on the specified server and port.
 * The daemon will attempt to run the command defined as [command].  Program output and
 * return code are sent back from the daemon and displayed as this plugin's own output and
 * return code.
 *
 * Command line: CHECK_NRPE -H <host_address> [-p port] [-c command] [-to to_sec]
 *
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "utils.h"

#define DEFAULT_NRPE_COMMAND	"_NRPE_CHECK"	/* check version of NRPE daemon */

#ifdef HAVE_SSL
#include <openssl/ssl.h>

struct ssl_data {
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
};
#endif

struct check_nrpe {
	int server_port;
	char *server_name;
	char *command_name;
	int socket_timeout;
	int timeout_return_code;
	int sd;

	char query[MAX_INPUT_BUFFER];

	int show_help;
	int show_license;
	int show_version;

	int use_ssl;
#ifdef HAVE_SSL
	struct ssl_data ssl;
#endif
};

struct check_nrpe global;

/*
 * Just sets the global data structure to something sane.
 */
static void initialize_global(void) {
	global.server_port = DEFAULT_SERVER_PORT;
	global.server_name = NULL;
	global.command_name = NULL;
	global.socket_timeout = DEFAULT_SOCKET_TIMEOUT;
	global.timeout_return_code = STATE_CRITICAL;
	memset(global.query,sizeof(global.query),0);
	global.show_help = FALSE;
	global.show_license = FALSE;
	global.show_version = FALSE;
#ifdef HAVE_SSL
	global.use_ssl = TRUE;
#else
	global.use_ssl = FALSE;
#endif
}

static void usage(void)
{
	printf ("Usage: check_nrpe -H <host> [-n] [-u] [-p <port>] [-t <timeout>] [-c <command>] [-a <arglist...>]\n");
	printf("\n");
	printf("Options:\n");
	printf(" -n         = Do no use SSL\n");
	printf (" -u         = Make socket timeouts return an UNKNOWN state instead of CRITICAL\n");
	printf (" <host>     = The address of the host running the NRPE daemon\n");
	printf (" [port]     = The port on which the daemon is running (default=%d)\n",
		 DEFAULT_SERVER_PORT);
	printf (" [timeout]  = Number of seconds before connection times out (default=%d)\n",
		 DEFAULT_SOCKET_TIMEOUT);
	printf (" [command]  = The name of the command that the remote daemon should run\n");
	printf (" [arglist]  = Optional arguments that should be passed to the command.  Multiple\n");
	printf ("              arguments should be separated by a space.  If provided, this must be\n");
	printf ("              the last option supplied on the command line.\n");
	printf("\n");
	printf("Note:\n");
	printf ("This plugin requires that you have the NRPE daemon running on the remote host.\n");
	printf ("You must also have configured the daemon to associate a specific plugin command\n");
	printf ("with the [command] option you are specifying here.  Upon receipt of the\n");
	printf ("[command] argument, the NRPE daemon will run the appropriate plugin command and\n");
	printf ("send the plugin output and return code back to *this* plugin.  This allows you\n");
	printf ("to execute plugins on remote hosts and 'fake' the results to make Nagios think\n");
	printf("the plugin is being run locally.\n");
	printf("\n");
}

#define OPTCHARS "H:c:a:t:p:nuhl"
static int process_arguments(int argc, char **argv)
{
	int argindex = 0;
	int c = 1;
	int i = 1;

#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option long_options[] = {
		{"host", required_argument, 0, 'H'},
		{"command", required_argument, 0, 'c'},
		{"args", required_argument, 0, 'a'},
		{"no-ssl", no_argument, 0, 'n'},
		{"unknown-timeout", no_argument, 0, 'u'},
		{"timeout", required_argument, 0, 't'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
		{0, 0, 0, 0}
	};
#endif

	/* no options were supplied */
	if (argc < 2)
		return ERROR;

	while (1) {
#ifdef HAVE_GETOPT_LONG
		c = getopt_long(argc, argv, OPTCHARS, long_options,
				&option_index);
#else
		c = getopt(argc, argv, OPTCHARS);
#endif
		if (c == -1 || c == EOF)
			break;

		/* process all arguments */
		switch (c) {

		case '?':
		case 'h':
			global.show_help = TRUE;
			break;
		case 'V':
			global.show_version = TRUE;
			break;
		case 'l':
			global.show_license = TRUE;
			break;
		case 't':
			global.socket_timeout = atoi(optarg);
			if (global.socket_timeout <= 0)
				return ERROR;
			break;
		case 'p':
			global.server_port = atoi(optarg);
			if (global.server_port <= 0)
				return ERROR;
			break;
		case 'H':
			global.server_name = strdup(optarg);
			break;
		case 'c':
			global.command_name = strdup(optarg);
			break;
		case 'a':
			argindex = optind;
			break;
		case 'n':
			global.use_ssl = FALSE;
			break;
		case 'u':
			global.timeout_return_code = STATE_UNKNOWN;
			break;
		default:
			return ERROR;
			break;
		}
	}

	/* FIXME: Check size properly instead of cutting off the end */
	snprintf(global.query, sizeof(global.query), "%s",
		 (global.command_name == NULL) ? DEFAULT_NRPE_COMMAND : global.command_name);
	global.query[sizeof(global.query) - 1] = '\x0';

	/* get the command args */
	if (argindex > 0) {

		for (c = argindex - 1; c < argc; c++) {

			i = sizeof(global.query) - strlen(global.query) - 2;
			if (i <= 0)
				break;

			strcat(global.query, "!");
			strncat(global.query, argv[c], i);
			global.query[sizeof(global.query) - 1] = '\x0';
		}
	}

	/* make sure required args were supplied */
	if (global.server_name == NULL && global.show_help == FALSE && global.show_version == FALSE
	    && global.show_license == FALSE)
		return ERROR;

	return OK;
}

static void alarm_handler(int __attribute__((unused)) sig)
{
	printf("CHECK_NRPE: Socket timeout after %d seconds.\n",
	       global.socket_timeout);

	exit(global.timeout_return_code);
}

/* submitted by Mark Plaksin 08/31/2006 */
static int graceful_close(int sd, int timeout)
{
	fd_set in;
	struct timeval tv;
	char buf[1000];

	/* send FIN packet */
	shutdown(sd, SHUT_WR);
	for (;;) {

		FD_ZERO(&in);
		FD_SET(sd, &in);
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		/* timeout or error */
		if (1 != select(sd + 1, &in, NULL, NULL, &tv))
			break;

		/* no more data (FIN or RST) */
		if (0 >= recv(sd, buf, sizeof(buf), 0))
			break;
	}

#ifdef HAVE_CLOSESOCKET
	closesocket(sd);
#else
	close(sd);
#endif

	return OK;
}
int main(int argc, char **argv)
{
	uint32_t packet_crc32;
	uint32_t calculated_crc32;
	int16_t result;
	int rc;
	packet send_packet;
	packet receive_packet;
	int bytes_to_send;
	int bytes_to_recv;

	initialize_global();
	result = process_arguments(argc, argv);

	if (result != OK || global.show_help == TRUE || global.show_license == TRUE
	    || global.show_version == TRUE) {

		if (result != OK)
			printf("Incorrect command line arguments supplied\n");
		printf("\n");
		printf("NRPE Plugin for Nagios\n");
		printf
		    ("Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)\n");
		printf("Version: %s\n", PROGRAM_VERSION);
		printf("Last Modified: %s\n", MODIFICATION_DATE);
		printf("License: GPL v2 with exemptions (-l for more info)\n");
#ifdef HAVE_SSL
		printf
		    ("SSL/TLS Available: Anonymous DH Mode, OpenSSL 0.9.6 or higher required\n");
#endif
		printf("\n");
	}

	if (result != OK || global.show_help == TRUE)
		usage();	

	if (global.show_license == TRUE)
		display_license();

	if (result != OK || global.show_help == TRUE || global.show_license == TRUE
	    || global.show_version == TRUE)
		exit(STATE_UNKNOWN);

	/* generate the CRC 32 table */
	generate_crc32_table();

#ifdef HAVE_SSL
	/* initialize SSL */
	if (global.use_ssl == TRUE) {
		SSL_library_init();
		SSLeay_add_ssl_algorithms();
		global.ssl.meth = SSLv23_client_method();
		SSL_load_error_strings();
		if ((global.ssl.ctx = SSL_CTX_new(global.ssl.meth)) == NULL)
			exit_crit("Could not create SSL context.");

		/* ADDED 01/19/2004 */
		/* use only TLSv1 protocol */
		SSL_CTX_set_options(global.ssl.ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	}
#endif

	/* initialize alarm signal handling */
	signal(SIGALRM, alarm_handler);

	/* set socket timeout */
	alarm(global.socket_timeout);

	/* try to connect to the host at the given port number */
	result = my_tcp_connect(global.server_name, global.server_port, &global.sd);

#ifdef HAVE_SSL
	/* do SSL handshake */
	if (result == STATE_OK && global.use_ssl == TRUE) {
		if ((global.ssl.ssl = SSL_new(global.ssl.ctx)) != NULL) {
			SSL_CTX_set_cipher_list(global.ssl.ctx, "ADH");
			SSL_set_fd(global.ssl.ssl, global.sd);
			if ((rc = SSL_connect(global.ssl.ssl)) != 1)
				exit_crit("Could not complete SSL handshake.");
		} else {
			exit_crit("Could not create SSL connection structure.");
		}

		/* bail if we had errors */
		if (result != STATE_OK) {
			SSL_CTX_free(global.ssl.ctx);
			close(global.sd);
			exit(result);
		}
	}
#endif

	/* we're connected and ready to go */
	if (result == STATE_OK) {

		/* clear the packet buffer */
		bzero(&send_packet, sizeof(send_packet));

		/* fill the packet with semi-random data */
		randomize_buffer((char *)&send_packet, sizeof(send_packet));

		/* initialize packet data */
		send_packet.packet_version =
		    (int16_t) htons(NRPE_PACKET_VERSION_2);
		send_packet.packet_type = (int16_t) htons(QUERY_PACKET);
		strncpy(&send_packet.buffer[0], global.query, MAX_PACKETBUFFER_LENGTH);
		send_packet.buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';

		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value = (u_int32_t) 0L;
		calculated_crc32 =
		    calculate_crc32((char *)&send_packet, sizeof(send_packet));
		send_packet.crc32_value = (u_int32_t) htonl(calculated_crc32);

		/***** ENCRYPT REQUEST *****/

		/* send the packet */
		bytes_to_send = sizeof(send_packet);
		if (global.use_ssl == FALSE)
			rc = sendall(global.sd, (char *)&send_packet, &bytes_to_send);
#ifdef HAVE_SSL
		else {
			rc = SSL_write(global.ssl.ssl, &send_packet, bytes_to_send);
			if (rc < 0)
				rc = -1;
		}
#endif
		/*
		 * FIXME: Should be unknown, not crit.
		 */
		if (rc == -1) {
			close(global.sd);
			exit_crit("Error sending query to host.");
		}

		/* wait for the response packet */
		bytes_to_recv = sizeof(receive_packet);
		if (global.use_ssl == FALSE)
			rc = recvall(global.sd, (char *)&receive_packet,
				     &bytes_to_recv, global.socket_timeout);
#ifdef HAVE_SSL
		else
			rc = SSL_read(global.ssl.ssl, &receive_packet, bytes_to_recv);
#endif

		/* reset timeout */
		alarm(0);

		/* close the connection */
#ifdef HAVE_SSL
		if (global.use_ssl == TRUE) {
			SSL_shutdown(global.ssl.ssl);
			SSL_free(global.ssl.ssl);
			SSL_CTX_free(global.ssl.ctx);
		}
#endif
		graceful_close(global.sd, 1000);

		if (rc < 0)
			exit_unknown("Error receiving data from daemon.");
		else if (rc == 0)
			exit_unknown("Received 0 bytes from daemon.  Check the remote server logs for error messages.");
		else if (bytes_to_recv < sizeof(receive_packet))
			exit_unknown("Receive underflow - only %d bytes received (%lu expected).",
			     bytes_to_recv, sizeof(receive_packet));

		/***** DECRYPT RESPONSE *****/

		/* check the crc 32 value */
		packet_crc32 = ntohl(receive_packet.crc32_value);
		receive_packet.crc32_value = 0L;
		calculated_crc32 =
		    calculate_crc32((char *)&receive_packet,
				    sizeof(receive_packet));
		if (packet_crc32 != calculated_crc32) {
			close(global.sd);
			exit_unknown("Response packet had invalid CRC32.");
		}

		/* check packet version */
		if (ntohs(receive_packet.packet_version) !=
			NRPE_PACKET_VERSION_2) {
			close(global.sd);
			exit_unknown("Invalid packet version received from server.");
		}

		/* check packet type */
		if (ntohs(receive_packet.packet_type) != RESPONSE_PACKET) {
			close(global.sd);
			exit_unknown("Invalid packet type received from server.");
		}

		/* get the return code from the remote plugin */
		result = (int16_t) ntohs(receive_packet.result_code);

		/* print the output returned by the daemon */
		receive_packet.buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		if (!strcmp(receive_packet.buffer, ""))
			printf("CHECK_NRPE: No output returned from daemon.\n");
		else
			printf("%s\n", receive_packet.buffer);
	}

	/* reset the alarm */
	else
		alarm(0);

	return result;
}

