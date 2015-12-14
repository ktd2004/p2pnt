/*
 * Copyright (C) 2009 Chang Min Lee <chngmn@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details. (/COPYING)
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "server.h"
#include "types.h"
#include <stdio.h>

#define DEFAULT_RDV_SERVER_PORT 51014

int main (int argc, char *argv[]) 
{
	//Binding address
	ENetAddress address;
	address.host = ENET_HOST_ANY;
	address.port = DEFAULT_RDV_SERVER_PORT;

	//NAT Traversal 테스트를 위한 최대 클라이언트 개수
	int max_client = atoi (argv[1]);

	if (enet_initialize () != 0)
	{
		fprintf (stderr, "An error occurred while initializing ENet.\n");
		return EXIT_FAILURE;
	}
	atexit (enet_deinitialize);

	create_server (max_client, address);
	run_server();
	destroy_server();

	return 0;
}