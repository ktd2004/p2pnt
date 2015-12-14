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
#include "rendezvous.h"
#include "rdvmsg.h"
#include <stdio.h>
#include <assert.h>

#define MAX_CLIENT 256

#define SERVER (g_srv)
#define RENDEZVOUS_MANAGER (g_srv.sg_manager)

typedef struct rdv_client
{
	unsigned int	usn;
	ENetPeer		*peer;
	
	//sd정보가 있는 로그인메세지를 임시로 저장
	rdv_msg		*login_msg;
	
} rdv_client;

typedef struct rdv_server
{
	ENetHost *host;

	rdv_client *client[MAX_CLIENT];

	//랑데부 객체
	rendezvous_manager *sg_manager;

	//클라이언트의 응답에 사용하기 위한 버퍼
	unsigned char *send_pkt;
	size_t max_pkt_len;
	
} rdv_server;

static void add_client_to_srv (rdv_client *client);
static void del_client_to_srv (rdv_client *client);

static void create_client (rdv_client **p_client);
static void destroy_client (rdv_client *client);
static rdv_client * find_client (unsigned int usn);

//////////////////
/// ENet Handlers
//////////////////
static void handle_connect (ENetEvent *event);
static void handle_receive (ENetEvent *event);
static void handle_disconnect (ENetEvent *event);

static int respond_to_login (ENetPeer *peer, unsigned int usn);



static void on_result (unsigned int usn, 
					   unsigned int target_usn, 
					   const unsigned char *sd, 
					   unsigned sd_length);


//////////
/// global
//////////
rdv_server g_srv;


int create_server (unsigned max_client_for_rendezvous, 
				   ENetAddress address) 
{
	p2p_status_t status;
	SERVER.host = enet_host_create (&address, 1000,0,0);
   
	if (SERVER.host == NULL)
	{
		fprintf (stderr, "An error occurred while trying to create an ENet g_srv host.\n");
		exit (EXIT_FAILURE);
	}

	rendezvous_cb cb;
	cb.on_result = &on_result;

	status = rendezvous_manager_create (max_client_for_rendezvous, 
										cb, &RENDEZVOUS_MANAGER);
	assert (0 == status);

	SERVER.max_pkt_len = 1500;
	SERVER.send_pkt = (unsigned char *) malloc (SERVER.max_pkt_len);
	assert (SERVER.send_pkt);
	
	printf ("server created successfully\n");
	return 0;
}

void run_server () 
{ 

  ENetEvent event;
  
  printf ("server started (max = %d, cur = %d)...\n", 
	  rendezvous_manager_capacity(RENDEZVOUS_MANAGER), 
	  rendezvous_manager_get_sd_count(RENDEZVOUS_MANAGER)); 
	
  while (enet_host_service (SERVER.host, & event, 100) >= 0)  
  {
    switch (event.type) 
    {    
    case ENET_EVENT_TYPE_CONNECT:    
			handle_connect (&event);
            break;

    case ENET_EVENT_TYPE_RECEIVE:
			handle_receive (&event);
            enet_packet_destroy (event.packet);
            break;           
          
    case ENET_EVENT_TYPE_DISCONNECT:
            handle_disconnect (&event);
			event.peer->data = 0;
			break;
    }
  }
}

void destroy_server ()
{
	free(SERVER.send_pkt);
	enet_host_destroy(SERVER.host);
}

/////////////////////
/// ENet handlers...
/////////////////////
static void handle_connect (ENetEvent *event) 
{
	static unsigned int usn_allocator = 0;
	
	if (0 == rendezvous_manager_is_full(RENDEZVOUS_MANAGER))
	{
		assert (!"server is full!");
	}

	rdv_client *c = 0;
	create_client (&c);
	assert (c);

	c->usn = ++usn_allocator;
	
	event->peer->data = c;
	c->peer = event->peer;

	add_client_to_srv (c);

	printf ("Connected (count=%d) from %d.%d.%d.%d:%u\n", 
		rendezvous_manager_get_sd_count(RENDEZVOUS_MANAGER),
		(event->peer -> address.host << 24) >> 24,
		(event->peer -> address.host << 16) >> 24,
		(event->peer -> address.host << 8) >> 24,
		event->peer -> address.host >> 24,
		event->peer -> address.port);

}

static void handle_receive (ENetEvent *event)
{
	size_t parsed_len;
	int status;
	rdv_client *c;
	
	c = (rdv_client *)event->peer->data;
	assert (c);

	status = rdv_msg_decode (event->packet->data, 
								event->packet->dataLength, 
								c->login_msg, 
								&parsed_len, 
								NULL);
	assert (0 == status);

	//로그인
	if (RDV_LOGIN_REQUEST == c->login_msg->hdr.type)
	{
		int cur_sd_count;
		rdv_string_attr *string_attr;
		rdv_binary_attr *binary_attr;

		printf ("Login msg received (pkt size = %d)\n",event->packet->dataLength);

		string_attr = (rdv_string_attr *)rdv_msg_find_attr (c->login_msg, RDV_ATTR_ID, 0);
		assert (string_attr);

		binary_attr = (rdv_binary_attr *)rdv_msg_find_attr (c->login_msg, RDV_ATTR_SD, 0);
		assert (binary_attr);

		if (0 == rendezvous_manager_get_sd_count(RENDEZVOUS_MANAGER)) 
        {
			rendezvous_manager_reset_group (RENDEZVOUS_MANAGER);
		}

		cur_sd_count = rendezvous_manager_add_sd (RENDEZVOUS_MANAGER, 
													c->usn, 
													binary_attr->data, 
													binary_attr->length);
		assert (0 != cur_sd_count);

		respond_to_login (event->peer, c->usn);
	}

	//P2P instruction
	if (0 == rendezvous_manager_is_full(RENDEZVOUS_MANAGER))
	{
		printf ("make session group!\n");
		int make_group_status = 
			rendezvous_manager_make_group (RENDEZVOUS_MANAGER);
		assert (0 == make_group_status);
	}
}

static void handle_disconnect (ENetEvent *event)
{
	rdv_client *c = (rdv_client*)event->peer->data;

	rendezvous_manager_del_sd (RENDEZVOUS_MANAGER, c->usn);

	del_client_to_srv(c);
	destroy_client (c);

	event->peer->data = 0;

	printf ("Disconnected (cur = %d)\n", 
		rendezvous_manager_get_sd_count (RENDEZVOUS_MANAGER));
}

static int respond_to_login (ENetPeer *peer, unsigned int usn)
{
	ENetPacket * packet;
	rdv_msg *msg;
	size_t pkt_size = 0;
	
	rdv_msg_create (RDV_LOGIN_RESPONSE, &msg);

	rdv_msg_add_uint_attr (msg, RDV_ATTR_USN, usn);
	rdv_msg_encode (msg, SERVER.send_pkt, SERVER.max_pkt_len, &pkt_size);

	packet = enet_packet_create (SERVER.send_pkt, 
									pkt_size,
									ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send (peer, 0, packet);
	enet_host_flush (SERVER.host);

	rdv_msg_destroy (msg);

	return 0;
}

static rdv_client * find_client (unsigned int usn)
{
  for (int i=0; i<MAX_CLIENT; ++i) 
	{
		rdv_client *c = SERVER.client[i];
		
		//사용중이 아니라면
		if (!c) 
		{ 
			continue;
		}

		if (usn == c->usn) {
			return c;
		}
	}

	return 0;
}

static void add_client_to_srv (rdv_client *client)
{
  for (int i=0; i<MAX_CLIENT; ++i) 
	{
		rdv_client *client2 = SERVER.client[i];
		if (!client2) {
			SERVER.client[i] = client;
			return;
		}
	}
}

static void del_client_to_srv (rdv_client *client)
{
  for (int i=0; i<MAX_CLIENT; ++i) 
	{
		rdv_client *client2 = SERVER.client[i];
		if (client2)
		{
			if (client2->usn == client->usn) 
			{
				SERVER.client[i] = 0;
				return;
			}
		}
	}
}

static void create_client (rdv_client **p_client)
{
	rdv_client *client = (rdv_client*) malloc (sizeof (rdv_client));
	int rc = rdv_msg_create (0, &client->login_msg);
	assert (0 == rc);
	*p_client = client;
}

static void destroy_client (rdv_client *client) 
{
	if (client) 
	{
	    rdv_msg_destroy (client->login_msg);
		free (client);
	}
}

static void on_result (unsigned int usn, 
					   unsigned int target_usn,
					   const unsigned char *sd, 
					   unsigned sd_length)
{
	ENetPacket * packet;
	rdv_msg *msg;
	size_t pkt_size = 0;
	rdv_client *c = find_client (usn);
	
	assert (c);

	rdv_msg_create (RDV_NEWUSER, &msg);
	rdv_msg_add_uint_attr (msg, RDV_ATTR_USN, target_usn);

	rdv_msg_add_binary_attr (msg, RDV_ATTR_SD, sd, sd_length);
	rdv_msg_encode (msg, SERVER.send_pkt, SERVER.max_pkt_len, &pkt_size);

	packet = enet_packet_create (SERVER.send_pkt, 
								pkt_size, 
								ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send (c->peer, 0, packet);
	enet_host_flush (SERVER.host);
	
	rdv_msg_destroy (msg);
}