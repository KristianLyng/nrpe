/************************************************************************
 *
 * COMMON.H - NRPE Common Include File
 * Copyright (c) 1999-2007 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 03-10-2008
 *
 * License:
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ************************************************************************/

#include "config.h"

#include <stdint.h>


#define OK		0
#define ERROR		-1

#define TRUE		1
#define FALSE		0

#define STATE_UNKNOWN  	3	/* service state return codes */
#define	STATE_CRITICAL 	2
#define STATE_WARNING 	1
#define STATE_OK       	0

/**************** PACKET STRUCTURE DEFINITION **********/

#define QUERY_PACKET		1	/* id code for a packet containing a query */
#define	RESPONSE_PACKET		2	/* id code for a packet containing a response */

#define NRPE_PACKET_VERSION_3   3	/* packet version identifier */
#define NRPE_PACKET_VERSION_2   2
#define NRPE_PACKET_VERSION_1	1	/* older packet version identifiers (no longer supported) */


typedef struct packet_struct {
	int16_t packet_version;
	int16_t packet_type;
	uint32_t crc32_value;
	int16_t result_code;
	char buffer[MAX_PACKETBUFFER_LENGTH];
} packet;
