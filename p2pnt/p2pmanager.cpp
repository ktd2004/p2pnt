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

#include "p2pmanager.h"
#include "p2p.h"
#include <pjlib.h>

#define STUN_SERVER_PORT 34780
#define TURN_SERVER_PORT 34780

#define TURN_USERNAME	"100"
#define TURN_PASSWD		"100"

#define SRV_DOMAIN		""

#define NO 0
#define YES 1

/////////////////////
/// p2pmanager
/////////////////////
typedef struct p2pmanager 
{
	struct options
	{
		unsigned				max_peers;
		
		char						stun_ip[PJ_MAX_HOSTNAME];
		pj_uint16_t			stun_port;

		char						turn_ip[PJ_MAX_HOSTNAME];
		pj_uint16_t			turn_port;
		
		pj_bool_t				is_rtt_check;
		unsigned				async_count;
		p2p_transport_cb	cb;
	} o;

	  
	pj_pool_t				*pool;
	pj_mutex_t			*lock;
	pj_dns_resolver	*resolver;
	pj_stun_config		stun_config;

	pj_bool_t				quit;

	pj_thread_t			*thread;

	pj_uint8_t			*sdbuf;

	p2p_peer				peer_list;
} p2pmanager;



/////////////
// callbacks
/////////////

static void on_rx_data (	pj_ice_strans				*ice_st, 
										unsigned						comp_id, 				
										void								*pkt, 					
										pj_size_t						size, 
										const pj_sockaddr_t	*src_addr, 
										unsigned						src_addr_len); 

static void on_ice_complete (	pj_ice_strans			*ice_st, 
												pj_ice_strans_op		op, 
												pj_status_t				status); 

////////////
/// 스레드
////////////
static int worker_thread (void *arg);

///////////////////////
// p2p_peer 조회 함수
///////////////////////

void print_cands (p2p_peer *p);

static pj_bool_t find_peer_by_idx (pj_uint32_t idx, p2p_peer **p);

static pj_bool_t find_peer (pj_uint32_t usn, p2p_peer **out);

static int compare_find (void *value, const pj_list_type *node);

static int compare_no_inited (void *value, const pj_list_type *node);
static pj_bool_t is_all_ready ();

///////////////////
/// ICE 설정 함수
///////////////////

//STUN 설정
static pj_status_t create_stun_config (pj_pool_t *pool, pj_stun_config *stun_cfg);

//ICE 설정
static pj_status_t create_ice_strans_config(pj_ice_strans_cfg		*ice_cfg, 
																	unsigned					enable_host,
																	unsigned					enable_stun, 
																	unsigned					enable_turn,
																	const char				stun_ip[],
																	pj_uint16_t				stun_port,
																	const char				turn_ip[],
																	pj_uint16_t				turn_port);


static void nat_detect_cb (	void *user_data, 
											const pj_stun_nat_detect_result *res);


///////////////
//global variables
///////////////

pj_pool_factory *mem;
pj_caching_pool caching_pool;


//////////
//컨트롤러
//////////
p2pmanager g_p2pmanager;

//////////
// p2p api
//////////

int p2p_init()
{
	pj_status_t status;

	status = pj_init ();
	PJ_ASSERT_RETURN (status == PJ_SUCCESS, -1);

	status = pjlib_util_init();
	PJ_ASSERT_RETURN  (status == PJ_SUCCESS, -1);

	status = pjnath_init();
	PJ_ASSERT_RETURN (status == PJ_SUCCESS, -1);

	return 0;
}

void p2p_shutdown()
{
	pj_shutdown();
}

int p2p_manager_create (unsigned			max_peers,
						const char			*stun_ip,
						p2p_uint16_t		stun_port,
						const char			*turn_ip,
						p2p_uint16_t		turn_port,
						p2p_bool_t			is_rtt_check,
						unsigned			async_count,
						p2p_transport_cb	cb)
{
	pj_status_t status;
	pj_sockaddr hostip;
	
	PJ_ASSERT_RETURN (max_peers > 0, -2);

	//pj_dump_config();
	pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);

	pj_log_set_level(0);
	pj_log_set_decor(PJ_LOG_HAS_NEWLINE | PJ_LOG_HAS_TIME | PJ_LOG_HAS_MICRO_SEC | PJ_LOG_HAS_COLOR);

	mem = &caching_pool.factory;

	//옵션
	g_p2pmanager.o.max_peers = max_peers;
	g_p2pmanager.o.cb = cb;
	g_p2pmanager.o.is_rtt_check = is_rtt_check;
	g_p2pmanager.o.async_count = async_count;
	
	//enable STUN?
	pj_bzero (g_p2pmanager.o.stun_ip, sizeof (g_p2pmanager.o.stun_ip));
	if (stun_ip) {
		pj_memcpy (g_p2pmanager.o.stun_ip, stun_ip, strlen (stun_ip));
		g_p2pmanager.o.stun_port = stun_port;
	}

	//enable TURN?
	pj_bzero (g_p2pmanager.o.turn_ip, sizeof (g_p2pmanager.o.turn_ip));
	if (turn_ip){
		pj_memcpy (g_p2pmanager.o.turn_ip, turn_ip, strlen (turn_ip));
		g_p2pmanager.o.turn_port = turn_port;
	}

	//메모리풀 생성
	g_p2pmanager.pool = pj_pool_create (mem, 
										NULL, 
										10000, 
										5000, 
										NULL); 

	//Lock
	pj_mutex_create_recursive (	g_p2pmanager.pool, 
								0, 
								&g_p2pmanager.lock);
  
	//리스트 초기화
	pj_list_init (&g_p2pmanager.peer_list);

  
	status = pj_gethostip(pj_AF_INET(), &hostip);
  
	if (status != PJ_SUCCESS) {
		return -1;
	}

	//시스템 STUN 설정
    status = create_stun_config(g_p2pmanager.pool, 
								&g_p2pmanager.stun_config);
    if (status != PJ_SUCCESS) {
		pj_pool_release(g_p2pmanager.pool);
		return -1;
	}

    for (unsigned i = 0; i < max_peers; ++i)
    {
		p2p_peer *p;
		pj_ice_strans_cfg ice_cfg;
		pj_ice_strans_cb ice_cb;

		p = PJ_POOL_ZALLOC_T (g_p2pmanager.pool, p2p_peer);
		pj_assert (p);

		//ICE 설정
		status = create_ice_strans_config (&ice_cfg,
										   YES, //host
										   stun_ip ? YES : NO,   //stun
										   turn_ip ? YES : NO,   //turn
										   g_p2pmanager.o.stun_ip,
										   stun_port,
										   g_p2pmanager.o.turn_ip,
										   turn_port);

		if (status != PJ_SUCCESS) {
		  return -1;
		}
		  
		//STUN설정을 공유한다
		ice_cfg.stun_cfg = g_p2pmanager.stun_config;

		/* Init callback structure */
		pj_bzero (&ice_cb, sizeof(ice_cb));
		ice_cb.on_rx_data = &on_rx_data;
		ice_cb.on_ice_complete = &on_ice_complete;

		//create p2p_peer
		status = p2p_peer_create (&ice_cfg, ice_cb, 50000, p);
		pj_assert (status == PJ_SUCCESS);
    
		p->idx = i+1;

		if (status != PJ_SUCCESS) 
		{
		}
		pj_list_push_back (&g_p2pmanager.peer_list, p);

	}
  
	g_p2pmanager.quit = PJ_FALSE;
	g_p2pmanager.sdbuf = 0;
	status = pj_thread_create(	g_p2pmanager.pool, 
								"worker%p", 
								&worker_thread,
								&g_p2pmanager,   
								0,//PJ_THREAD_DEFAULT_STACK_SIZE, 
								0, 
								&g_p2pmanager.thread);

	pj_assert (status == PJ_SUCCESS);

	return status;
}

int p2p_manager_make_session (p2p_uint32_t usn, 
							  const p2p_uint8_t *sd, 
							  unsigned sd_length)
{
	p2p_peer *peer = 0;
	pj_uint32_t idx;

	pj_uint8_t *sd2 = (pj_uint8_t *)sd;
	unsigned sd_length2;

	idx = GETVAL32H (sd2, 0);
	sd2 += 4;
	sd_length2 = sd_length - 4;

	if (PJ_TRUE == find_peer_by_idx (idx, &peer)) 
	{
		pj_assert (peer);

		pj_status_t status;
		status = p2p_peer_start (peer, usn, sd2, sd_length2);

		pj_assert (status == PJ_SUCCESS);
		if (status != PJ_SUCCESS) {
		  return -1;
		}

		return 0;
	}

	return -1;
}

void p2p_manager_break_session (p2p_uint32_t usn)
{
	pj_status_t status;
	p2p_peer *peer;

	if (PJ_TRUE == find_peer (usn, &peer)) 
	{
		//피어세션을 중지한다
		p2p_peer_stop (peer);

		//재사용을 위해 다시 초기화해준다
		status = p2p_peer_init (peer);
		pj_assert (status == PJ_SUCCESS);
	}
}

void p2p_manager_destroy ()
{
	g_p2pmanager.quit = PJ_TRUE;

	//pj_thread_resume (g_p2pmanager.thread);
	pj_thread_join (g_p2pmanager.thread);
	g_p2pmanager.thread = NULL;
       
    pj_mutex_destroy (g_p2pmanager.lock);

    pj_timer_heap_destroy (g_p2pmanager.stun_config.timer_heap);
    pj_ioqueue_destroy (g_p2pmanager.stun_config.ioqueue);
    pj_pool_release (g_p2pmanager.pool);
}

int p2p_manager_sendto(p2p_uint32_t usn, 
					   const void *pkt, 
					   unsigned pkt_length)
{
	pj_status_t status;	
	pj_bool_t b;
	p2p_peer *p;
	
	b = find_peer (usn, &p);
	pj_assert(b == PJ_TRUE);
	pj_assert (usn == p2p_peer_get_usn (p));

	if (pkt && pkt_length && p) 
	{
		status = p2p_peer_sendto (p, pkt, pkt_length);
		pj_assert (status == PJ_SUCCESS);
	}

    return status;
}
                          
//controller에서 로컬피어에 대한 정보를 관리한다
unsigned p2p_manager_get_local_sd (p2p_uint8_t **p_sd)
{
	pj_status_t status;

	pj_uint8_t *sd, *start;
	unsigned sd_len;

	if (g_p2pmanager.sdbuf) {
		sd = g_p2pmanager.sdbuf;
	}
	else {
		sd = (pj_uint8_t *) pj_pool_alloc (g_p2pmanager.pool, 160 * PJ_ICE_MAX_CAND);
		g_p2pmanager.sdbuf = sd;
	}

	start = sd;
	sd_len = 0;

    p2p_peer *iter = g_p2pmanager.peer_list.next;

    while (iter != &g_p2pmanager.peer_list)
    {
		pj_ice_sess_cand cand[PJ_ICE_MAX_CAND];
		unsigned cand_count = PJ_ICE_MAX_CAND; 

		p2p_peer *next = iter->next;

		pj_uint8_t *temp_sd;
		unsigned temp_sd_len;

		//enum candidates
		status = p2p_peer_enum_cands (iter, &cand_count, cand);
		pj_assert (status == PJ_SUCCESS);

		//encoding
		temp_sd_len = p2p_encode_sd (g_p2pmanager.pool,
									cand, 
									cand_count,
									&temp_sd);

		//set length
		//실제 사용되는 sd의 크기는 temp_sd_len이다
		//그러나 외부세계에서는 idx길이까지 포함된 temp_sd_len+4이다
		PUTVAL32H (sd, 0, temp_sd_len + 4);
		sd += 4;
		sd_len += 4;
		
		//set peer idx
		PUTVAL32H (sd, 0, iter->idx);
		sd += 4;
		sd_len += 4;
		
		//set sd
		pj_memcpy (sd, temp_sd, temp_sd_len);
		sd += temp_sd_len;
		sd_len += temp_sd_len;
    
		iter = next;
	}

	pj_assert ((sd - start) == sd_len);

	if (*p_sd && sd_len) {
		*p_sd = start;
	}

    return sd_len;
}

p2p_status_t p2p_stun_detect_nat_type(p2p_manager_stun_nat_detect_cb *cb)
{
	pj_sockaddr_in server;
	//pj_str_t stunip = pj_str (g_p2pmanager.o.stun_ip);
	//pj_str_t stunip = pj_str ("127.0.0.1");
	//pj_sockaddr_in_init (&server, &stunip, g_p2pmanager.o.stun_port);
	//pj_sockaddr_in_init (&server, &stunip, 3478);

	/*
	return pj_stun_detect_nat_type (&server,
		&g_p2pmanager.stun_config,
		cb,
		&nat_detect_cb);
		*/
	return -1;
}



/////////////
/// Helper
/////////////

pj_bool_t is_all_ready ()
{
	int state = P2P_PEER_RUNNING;
	p2p_peer *out = (p2p_peer *) pj_list_search (&g_p2pmanager.peer_list, &state, compare_no_inited);    
	if(out) {
		return PJ_FALSE;
	}
	
	return PJ_TRUE;
}

pj_bool_t find_peer_by_idx (pj_uint32_t idx, p2p_peer **out)
{
  p2p_peer *it = g_p2pmanager.peer_list.next;
  while (it != &g_p2pmanager.peer_list)
  {
    p2p_peer *next = it->next;
	if (idx == it->idx) {
      *out = it;
      return PJ_TRUE;
    }
    it = next;
  }

  return PJ_FALSE;  
}

pj_bool_t find_peer (pj_uint32_t usn, p2p_peer **out)
{
  *out = (p2p_peer *) pj_list_search (&g_p2pmanager.peer_list, &usn, compare_find);    
  if(*out) {
    return PJ_TRUE;
  }
  return PJ_FALSE;
}

int compare_find (void *value, const pj_list_type *node)
{
  pj_assert (node);
 
  unsigned usn;
  usn = p2p_peer_get_usn ((p2p_peer*)node);

  if (0 == pj_memcmp (value, &usn, sizeof (unsigned)))
    return 0;

  return -1;
}

int compare_no_inited(void *value, const pj_list_type *node)
{
  pj_assert (node);
 
  int state1 = P2P_PEER_INITED;
  int state2 = p2p_peer_get_state ((p2p_peer*)node);

  if (0 != pj_memcmp (&state1, &state2, sizeof (int)))
    return 0;

  return -1;
}

pj_status_t create_stun_config (pj_pool_t *pool, pj_stun_config *stun_cfg)
{
  pj_ioqueue_t *ioqueue;
  pj_timer_heap_t *timer_heap;
  pj_status_t status;
  
  stun_cfg->pf = mem;

  status = pj_ioqueue_create(pool, 64, &ioqueue);
  if (status != PJ_SUCCESS) {
	  return status;
  }

  status = pj_timer_heap_create(pool, 256, &timer_heap);
  if (status != PJ_SUCCESS) {
	  pj_ioqueue_destroy(ioqueue);
	  return status;
  }

  pj_stun_config_init(stun_cfg, mem, 0, ioqueue, timer_heap);

  return PJ_SUCCESS;
}

pj_status_t create_ice_strans_config(pj_ice_strans_cfg	*ice_cfg,
									unsigned			enable_host,
									unsigned			enable_stun,
									unsigned			enable_turn,
									const char			stun_ip[],
									pj_uint16_t			stun_port,
									const char			turn_ip[],
									pj_uint16_t			turn_port)
{
  pj_assert (ice_cfg);

  /* Init ICE stream transport configuration structure */
  pj_ice_strans_cfg_default (ice_cfg);

  if (enable_host == YES) 
	{
	  ice_cfg->stun.no_host_cands = PJ_FALSE;
		ice_cfg->stun.loop_addr = PJ_FALSE;
  } 
	else 
	{
	  ice_cfg->stun.no_host_cands = PJ_TRUE;
  }

  if (enable_stun & YES) 
	{
  //  if ((enable_stun & SRV) == SRV)
  //    ice_cfg->stun.server = pj_str(SRV_DOMAIN);
  //  else
				ice_cfg->stun.server = pj_str((char *)stun_ip);
    ice_cfg->stun.port = stun_port;
  }
	else {
		ice_cfg->stun.server.slen = 0;
	}

	ice_cfg->stun.cfg.async_cnt = g_p2pmanager.o.async_count; //비동기 호출 수
    
  if (enable_turn & YES) 
	{
  //  if ((enable_turn & SRV) == SRV)
  //    ice_cfg->turn.server = pj_str(SRV_DOMAIN);
  //  else
				ice_cfg->turn.server = pj_str((char *)turn_ip);

    ice_cfg->turn.port = turn_port;
	  ice_cfg->turn.conn_type = PJ_TURN_TP_UDP;
    ice_cfg->turn.auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
    ice_cfg->turn.auth_cred.data.static_cred.realm = pj_str(SRV_DOMAIN);
    ice_cfg->turn.auth_cred.data.static_cred.username = pj_str(TURN_USERNAME);
	  ice_cfg->turn.auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
	  ice_cfg->turn.auth_cred.data.static_cred.data = pj_str(TURN_PASSWD);
  }
	else {
		ice_cfg->turn.server.slen = 0;
	}

  return PJ_SUCCESS;
}

int worker_thread (void *p)
{ 
  int rc = 0;

  p2pmanager *c = (p2pmanager *) p;
  pj_assert (c);

  while (!c->quit) { 
		pj_time_val timeout = { 0, 100 };
		
		rc = pj_ioqueue_poll(c->stun_config.ioqueue, &timeout);
    if (rc < 0) {
	  char errbuf[256];
      pj_strerror (PJ_RETURN_OS_ERROR (rc), errbuf, sizeof (errbuf));
      PJ_LOG (2, ("worker", "error: %s\n", errbuf)); 
    }
		pj_timer_heap_poll(c->stun_config.timer_heap, NULL);
  }

  return rc;
}


//////////////
/// Callbacks
//////////////

static void on_rx_data(pj_ice_strans *ice_st, 
					   unsigned comp_id, void *pkt, 
					   pj_size_t size, 
					   const pj_sockaddr_t *src_addr, 
					   unsigned src_addr_len)
{
	PJ_UNUSED_ARG(pkt);
	PJ_UNUSED_ARG(size);
	PJ_UNUSED_ARG(src_addr);
	PJ_UNUSED_ARG(src_addr_len);

	p2p_peer *p = (p2p_peer*) pj_ice_strans_get_user_data(ice_st);
	pj_uint32_t usn = p2p_peer_get_usn (p);

	
	if (RTT_PING_MAGIC == (pj_uint32_t)GETVAL32H ((pj_uint8_t*)pkt, 0))
	{
		
		if ((pj_uint32_t)GETVAL32H ((pj_uint8_t*)pkt, 4) == usn) 
		{
			pj_time_val cur, t;

			pj_gettimeofday (&cur);
			t.sec = (long)GETVAL32H ((pj_uint8_t*)pkt, 12);
			t.msec = (long)GETVAL32H ((pj_uint8_t*)pkt, 16);
			PJ_TIME_VAL_SUB(cur, t);
				
			if (g_p2pmanager.o.cb.on_rtt_refresh) {
				(*g_p2pmanager.o.cb.on_rtt_refresh)(usn, PJ_TIME_VAL_MSEC(cur));
			}
		}
		else
		{
			//for debug...
			pj_thread_sleep ((pj_rand()+1) % 71);
			p2p_peer_sendto (p, pkt, (unsigned)size);
		}
	}
	else {
		if (g_p2pmanager.o.cb.on_rx_data) {
			(*g_p2pmanager.o.cb.on_rx_data)(usn, pkt, size);
		}	
	}
}

static void on_ice_complete(pj_ice_strans *ice_st, pj_ice_strans_op op, pj_status_t status)
{
  p2p_peer *p;
  p = (p2p_peer *) pj_ice_strans_get_user_data(ice_st);

  switch (op) 
	{
    case PJ_ICE_STRANS_OP_INIT:

			//후보의 갯수가 0인 상황도 대비해야한다
			//타이머를 통해 피어를 초기화 한다
			if (status == 0) 
			{
				status = p2p_peer_init (p);
				pj_assert (status == PJ_SUCCESS);

				if (is_all_ready ()) 
				{
					if (g_p2pmanager.o.cb.on_create) 
					{
						(*g_p2pmanager.o.cb.on_create)(status);
					}
				}
			}
	    break;

    case PJ_ICE_STRANS_OP_NEGOTIATION:
			if (status == PJ_SUCCESS) 
			{
                const pj_ice_sess_check *valid_pair = pj_ice_strans_get_valid_pair (ice_st, 1);
                pj_assert (valid_pair);
				pj_assert (PJ_TRUE == valid_pair->nominated);

                if (PJ_ICE_SESS_CHECK_STATE_SUCCEEDED == valid_pair->state)
                {
					{
						char addrinfo[PJ_INET_ADDRSTRLEN+10];
						char addrinfo2[PJ_INET_ADDRSTRLEN+10];
						printf ("LOCAL (%s, %s) --> REMOTE (%s, %s)\n", 
							pj_sockaddr_print(&valid_pair->lcand->addr, addrinfo, sizeof(addrinfo), 3),
							pj_ice_get_cand_type_name(valid_pair->lcand->type),
							pj_sockaddr_print(&valid_pair->rcand->addr, addrinfo2, sizeof(addrinfo2), 3),
							pj_ice_get_cand_type_name(valid_pair->rcand->type));
					}
                }

				if (g_p2pmanager.o.cb.on_ice_complete) 
				{
					/// callback
					(*g_p2pmanager.o.cb.on_ice_complete)(p2p_peer_get_usn (p), 
						(p2p_conn_type)p2p_peer_get_local_connection_type (p),
						(p2p_conn_type)p2p_peer_get_remote_connection_type(p),
						status);

					if(g_p2pmanager.o.is_rtt_check) {
						p2p_peer_start_rtt_est (p, g_p2pmanager.stun_config.timer_heap);
					}
				
				}
			}
      //PJ_EPENDING
	    break;

    default:
	    pj_assert(!"Unknown op");
    }
}

static void nat_detect_cb (void *user_data,
						   const pj_stun_nat_detect_result *res)
{
	if (user_data) {
		(*((p2p_manager_stun_nat_detect_cb*)user_data))((p2p_stun_nat_type)res->nat_type,
			pj_stun_get_nat_name (res->nat_type));
	}
}