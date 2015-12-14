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

#include <enet/enet.h>
#include <stdio.h>
#include <assert.h>
#include "p2pmanager.h"
#include "rdvmsg.h"

//커맨드라인 옵션을 위한
#include <pjlib-util.h>

#define TEST_ID	"MBOut"

#define DEFAULT_CONCURRENT_PEER_COUNT 2

#define DEFAULT_STUN_IP		"127.0.0.1"
#define DEFAULT_STUN_PORT	34780

#define DEFAULT_TURN_IP		DEFAULT_STUN_IP
#define DEFAULT_TURN_PORT	DEFAULT_STUN_PORT

#define DEFAULT_RDV_SERVER_IP	"127.0.0.1"
#define DEFAULT_RDV_SERVER_PORT 51014

typedef struct RdvTester
{
	struct option 
	{
		/// 동시연결 갯수
		p2p_uint32_t	concurrent_peers;

		char stunip[256];
		p2p_uint16_t	stun_port;
		
		char turnip[256];
		p2p_uint16_t	turn_port;
		
		/// rtt
		p2p_bool_t		rtt_check;

		/// 랑데부 서버 IP
		char			rdv_srv_ip[256];
		p2p_uint16_t	rdv_srv_port;
	} o;			
	
	/// ENet client
	ENetHost		*client;					

} RdvTester;


/// 아래는 P2P Library로 부터의 콜백을 처리하기 위한 함수이다.

static void on_create (p2p_status_t status);
static void on_rtt_refresh (p2p_uint32_t usn, unsigned msec);
static void on_rx_data (p2p_uint32_t usn, void *pkt, size_t pkt_length);
static void on_ice_complete (p2p_uint32_t usn, 
											 p2p_conn_type local_type, 
											 p2p_conn_type remote_type,
											 p2p_status_t status);

/// 랑데부서버용
p2p_bool_t init_enet ();
int run_event_loop ();

static void handle_connect		(ENetEvent *event);
static void handle_receive		(ENetEvent *event);
static void handle_disconnect (ENetEvent *event);

int login_to_rendezvous_server (ENetHost *host, ENetPeer *peer);

static p2p_status_t init_p2p_subsystem (int argc, char *argv[]);
static p2p_status_t create_p2p_subsystem ();
static void destroy_p2p_subsystem ();

/// tester global
static RdvTester tester;

static p2p_bool_t parse_arg (int argc, char *argv[]);

int main (int argc, char *argv[]) 
{	
	int rc = 0;
	
	if (P2P_SUCCESS != init_p2p_subsystem(argc, argv)) {
		fprintf (stderr, "init_p2p_subsystem() error!\n");
		return EXIT_FAILURE;
	}

	if (P2P_SUCCESS != create_p2p_subsystem()) {
		fprintf (stderr, "create_p2p_subsystem() error!\n");
		return EXIT_FAILURE;
	}

	rc = run_event_loop ();

	destroy_p2p_subsystem();
	return rc;
}

p2p_bool_t init_enet () 
{
  if (enet_initialize () != 0)
  {
    fprintf (stderr, "An error occurred while initializing ENet.\n");
   	return P2P_FALSE;
  }
	atexit (enet_deinitialize);

	tester.client = enet_host_create(0,1,0,0);
  if (tester.client == 0)
  {
    fprintf (stderr, "An error occurred while trying to create an ENet client host.\n");
   	return P2P_FALSE;
  }

	return P2P_TRUE;
}

int run_event_loop ()
{
	int rc;
	ENetEvent	event;
	enet_uint32 timeout;

	if (P2P_FALSE == init_enet ()) {
		fprintf (stderr, "enet error!\n");
		exit( EXIT_FAILURE);
	}

	timeout = 100;
	while ((rc = enet_host_service (tester.client, &event, timeout)) >= 0)
	{
		switch (event.type)
		{
		case ENET_EVENT_TYPE_CONNECT:   
			event.peer->data = &tester;
			handle_connect (&event);			
			
			break;
		case ENET_EVENT_TYPE_RECEIVE:
			handle_receive (&event);
			enet_packet_destroy (event.packet);
                 
			break;
               
		case ENET_EVENT_TYPE_DISCONNECT:
			handle_disconnect (&event);
			event.peer->data = 0;
		}
	}

	enet_host_destroy(tester.client);
	return rc;
}


void handle_connect (ENetEvent *event) 
{
	int rc;
	printf ("Session established successfully!\n");
	rc = login_to_rendezvous_server (tester.client, event->peer);
	assert (rc == 0);
}

void handle_receive (ENetEvent *event)
{
	int rc;
	rdv_msg msg;
	size_t parsed_len;

	//printf ("packet received (packet size=%d)\n",event->packet->dataLength);
	rc = rdv_msg_decode (event->packet->data, 
						 event->packet->dataLength, 
						 &msg,
						 &parsed_len, 
						 0);
	assert (rc == 0);

	
	if (RDV_LOGIN_RESPONSE == msg.hdr.type) /// 로그인 응답
	{
		rdv_uint_attr *uint_attr;
		uint_attr = (rdv_uint_attr *)rdv_msg_find_attr (&msg, RDV_ATTR_USN, 0);
		assert (uint_attr);
		
		printf ("received Login response from rendezvous server (my usn=%d)\n", uint_attr->value);
	}
	else if (RDV_NEWUSER == msg.hdr.type) ///새유저의 접속 알림
	{
		rdv_uint_attr *uint_attr;
		rdv_binary_attr *binary_attr;

		uint_attr = (rdv_uint_attr *)rdv_msg_find_attr (&msg, RDV_ATTR_USN, 0);
		assert (uint_attr);

		binary_attr = (rdv_binary_attr *)rdv_msg_find_attr (&msg, RDV_ATTR_SD, 0);
		assert (binary_attr);

		/// 세션 연결 시도 (홀펀칭 포함)
		rc = p2p_manager_make_session (uint_attr->value,				//usn 
								  binary_attr->data,			//sd
								  binary_attr->length); 
		assert (rc == 0);
	}
}

void handle_disconnect (ENetEvent *event)
{
	//do something...
}

void connect_to_rendezvous_server ()
{
  ENetAddress address;
  ENetPeer		*peer;

  enet_address_set_host (&address, tester.o.rdv_srv_ip);
  address.port = DEFAULT_RDV_SERVER_PORT;

  peer = enet_host_connect (tester.client, & address, 2);    
  if (peer == NULL)
  {  
	fprintf (stderr, "No available peers for initiating an ENet connection.\n");
    exit (EXIT_FAILURE);
  }

	peer->data = &tester;
}

int login_to_rendezvous_server (ENetHost *host, ENetPeer *peer) 
{
	ENetPacket *packet;
	int			status;
	
	rdv_msg			*msg;
	p2p_uint8_t		*pkt;

	int				max_pkt_len;
	size_t			pkt_size;

	p2p_uint8_t		*sd;
	unsigned		sd_length;

	status = rdv_msg_create (RDV_LOGIN_REQUEST, &msg);
	assert (status == 0);
	
	status = rdv_msg_add_string_attr (msg, RDV_ATTR_ID, TEST_ID);
	assert (status == 0);

	//get sd
	sd_length = p2p_manager_get_local_sd (&sd);
	assert (sd && sd_length);

	status = rdv_msg_add_binary_attr (msg, RDV_ATTR_SD, sd, sd_length);
	assert (status == 0);

	//malloc
	max_pkt_len = 1500;
	pkt = (p2p_uint8_t *) malloc (max_pkt_len);
	assert (pkt);

	//encoding
	status = rdv_msg_encode (msg, pkt, max_pkt_len, &pkt_size);
	assert (status == 0);

	

	packet = enet_packet_create (pkt, pkt_size, ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send (peer, 0, packet);

	enet_host_flush (host);
	
	printf ("sent Login request to rendezvous server (packet size=%d)\n", pkt_size);
	
	rdv_msg_destroy (msg);
	free (pkt);
	return 0;
}

static p2p_status_t init_p2p_subsystem (int argc, char *argv[])
{
	if (0 != p2p_init()) {
		return -1;
	}
	
	if (P2P_FALSE == parse_arg (argc, argv)) {
		fprintf (stderr, "parse error!\n");
		return -2;
	}

	return P2P_SUCCESS;
}

static p2p_status_t create_p2p_subsystem ()
{
	/// P2P 콜백함수를 지정한다
	p2p_transport_cb cb;

	cb.on_create = &on_create;
	cb.on_rtt_refresh = &on_rtt_refresh;
	cb.on_rx_data = &on_rx_data;
	cb.on_ice_complete = &on_ice_complete;

	return p2p_manager_create (tester.o.concurrent_peers,		//최대 피어 수
		tester.o.stunip,										//stun
		tester.o.stun_port,		
		tester.o.turnip,										//turn
		tester.o.turn_port,          
		P2P_TRUE == tester.o.rtt_check ? 1 : 0,					//rtt?
		1,														//async count
		cb);
}

static void destroy_p2p_subsystem ()
{
	p2p_manager_destroy ();
	p2p_shutdown();
}

////////////
// P2P 콜백
////////////

static void nat_detect_cb (p2p_stun_nat_type type, const char *natname)
{
	printf ("Your NAT-Type is %s\n", natname);
}

void on_create (p2p_status_t status)
{
	if(0==status) 
	{
		printf ("P2P library has initialized\n");
		connect_to_rendezvous_server ();
	}
}

void on_rtt_refresh (p2p_uint32_t usn, unsigned msec)
{
	printf ("RTT msec=%d (usn=%u)\n", msec, usn);
}

void on_rx_data (p2p_uint32_t usn, void *pkt, size_t pkt_length)
{
	printf ("on_rx_data (usn=%d, length=%d)\n", usn,pkt_length);
}

void on_ice_complete (p2p_uint32_t usn, 
					  p2p_conn_type local_type,
					  p2p_conn_type remote_type,
					  p2p_status_t status)
{
	if(0==status) 
	{
		printf ("Connectivity Checks is completed (peer usn = %u)\n", usn);
	}
}


p2p_bool_t parse_arg (int argc, char *argv[]) 
{
	int c;
	char *colon;
	pj_optind = 0;

	tester.o.concurrent_peers = DEFAULT_CONCURRENT_PEER_COUNT;
	
	memset (tester.o.stunip, '\0', sizeof (tester.o.stunip));
	strncpy_s (tester.o.stunip, DEFAULT_STUN_IP, strlen (DEFAULT_STUN_IP));		
	tester.o.stun_port = DEFAULT_STUN_PORT;

	memset (tester.o.turnip, '\0', sizeof (tester.o.turnip));
	strncpy_s (tester.o.turnip, DEFAULT_TURN_IP, strlen (DEFAULT_TURN_IP));		
	tester.o.turn_port = DEFAULT_TURN_PORT;
		
	tester.o.rtt_check = P2P_FALSE;

	memset (tester.o.rdv_srv_ip, '\0', sizeof (tester.o.rdv_srv_ip));
	strncpy_s (tester.o.rdv_srv_ip, DEFAULT_RDV_SERVER_IP, strlen (DEFAULT_RDV_SERVER_IP));		
	tester.o.rdv_srv_port = DEFAULT_RDV_SERVER_PORT;

	while ((c=pj_getopt(argc, argv, "c:s:t:rn")) !=-1) 
	{
		switch (c)
		{
		case 'c':
			tester.o.concurrent_peers = atoi(pj_optarg);  
			//tester.o.concurrent_peers = MAX_PEER;    
			break; 

		case 's': 
			//STUN address
			colon = strchr (pj_optarg, ':');
			if (colon) {
				*colon = 0;
				//port
				tester.o.stun_port = atoi (++colon);
			}
			//ip
			memset (tester.o.stunip, '\0', sizeof (tester.o.stunip));
			strncpy_s (tester.o.stunip, pj_optarg, strlen (pj_optarg));
			
			break;

		case 't':
			//TURN address
			colon = strchr (pj_optarg, ':');
			if (colon) {
				*colon = 0;
				//port
				tester.o.turn_port = atoi (++colon);
			}
			//ip
			memset (tester.o.turnip, '\0', sizeof (tester.o.turnip));
			strncpy_s (tester.o.turnip, pj_optarg, strlen (pj_optarg));				
			
			break;

		case 'r':			
			/// RTT
			tester.o.rtt_check = P2P_TRUE;
			break;

		case '?':
			break;
		}
	}

	if (argv[pj_optind] && strlen(argv[pj_optind])) 
	{
		colon = strchr (argv[pj_optind], ':');
		if (colon) {	
			*colon = 0;
			//port
			tester.o.rdv_srv_port = atoi (++colon);
		}

		memset (tester.o.rdv_srv_ip, '\0', sizeof (tester.o.rdv_srv_ip));
		strncpy_s (tester.o.rdv_srv_ip, argv[pj_optind], strlen (argv[pj_optind]));
		
		return P2P_TRUE;
	}

	return P2P_FALSE;
}