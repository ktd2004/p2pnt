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

#include "p2p.h"
#include <pjlib.h>

typedef struct p2p_peer_impl
{
  pj_uint32_t usn;

  p2p_peer *p;
  pj_pool_t	*pool;    

  pj_ice_strans	*ice_strans;	/* ICE stream transport		*/

  //session state
  int state;

  pj_mutex_t *lock;

  //for RTT
  pj_uint32_t		ping_count;
  pj_timer_heap_t	*timer;
  pj_timer_entry	*entry;
  pj_uint8_t		*rtt_buf;

} p2p_peer_impl;

#define PEER_IMPL(p) (p->impl)

static void rtt_callback (pj_timer_heap_t *ht, pj_timer_entry *e);
static void start_rtt_check (p2p_peer *p);

pj_status_t p2p_peer_create (pj_ice_strans_cfg *ice_cfg,           
							 const pj_ice_strans_cb ice_cb,
							 pj_uint16_t s_port,      
							 p2p_peer *p) 
{

  PJ_ASSERT_RETURN (ice_cfg, PJ_EINVAL);

  pj_pool_t *pool;

  pj_status_t status;
      
	//메모리풀 생성
  pool = pj_pool_create (ice_cfg->stun_cfg.pf, 0, 1000, 1000,0);  
  pj_assert (pool);

  PEER_IMPL(p) = PJ_POOL_ZALLOC_T (pool, p2p_peer_impl);
  pj_assert (PEER_IMPL(p));

  PEER_IMPL(p)->pool = pool;
  pj_mutex_create_recursive (PEER_IMPL(p)->pool, NULL, &PEER_IMPL(p)->lock);

  PEER_IMPL(p)->p = p;

  /* Create ICE stream transport */
  status = pj_ice_strans_create (NULL, 
								 ice_cfg, 
								 1, 
								 p, 
								 &ice_cb, 
								 &PEER_IMPL(p)->ice_strans); 

  pj_assert (status == PJ_SUCCESS);

  if (status != PJ_SUCCESS) {
		pj_pool_release (PEER_IMPL(p)->pool);
		pj_mutex_destroy (PEER_IMPL(p)->lock);
    return status;
  }
  
	//timer entry
	PEER_IMPL(p)->entry = (pj_timer_entry*) pj_pool_alloc (PEER_IMPL(p)->pool, 
															sizeof (pj_timer_entry));
	pj_assert (PEER_IMPL(p)->entry);

	//set user_data
	PEER_IMPL(p)->entry->user_data = p;
	//callback
	PEER_IMPL(p)->entry->cb = &rtt_callback;

	//ping buf
	PEER_IMPL(p)->rtt_buf = (pj_uint8_t*) pj_pool_zalloc (PEER_IMPL(p)->pool, 32);
	pj_assert (PEER_IMPL(p)->rtt_buf);

	//state
  PEER_IMPL(p)->state = P2P_PEER_CREATED;

  return PJ_SUCCESS;
}


pj_status_t p2p_peer_init (p2p_peer *p) 
{
	pj_assert (PEER_IMPL(p));
	pj_assert (PEER_IMPL(p)->state == P2P_PEER_CREATED);
	
	pj_status_t status;
    
	pj_str_t ufrag;	 
	pj_str_t passwd;

	//pj_create_unique_string(p->impl->pool, &ufrag);
	//pj_create_unique_string(p->impl->pool, &passwd);
	
	//for testing...
	ufrag =  pj_str ("100");
	passwd = pj_str ("100");

	status = pj_ice_strans_init_ice (PEER_IMPL(p)->ice_strans, 
				                     PJ_ICE_SESS_ROLE_CONTROLLING,
				                     &ufrag,
				                     &passwd);
	pj_assert (status == PJ_SUCCESS);
  
	if (status != PJ_SUCCESS) {   
		return status;  
	}
	
	PEER_IMPL(p)->usn = 0;
	PEER_IMPL(p)->state = P2P_PEER_INITED;

	return PJ_SUCCESS;
}

pj_status_t p2p_peer_start (p2p_peer *p, 
							pj_uint32_t usn,
							const pj_uint8_t *sd, 
							unsigned sd_len)
{
	pj_assert (PEER_IMPL(p));
  PJ_ASSERT_RETURN (p && sd, PJ_EINVAL);

  pj_status_t status;
  pj_str_t rem_ufrag, rem_passwd;

  pj_ice_sess_cand cand [PJ_ICE_MAX_CAND];
  unsigned cand_count = PJ_ICE_MAX_CAND;

  pj_bool_t decode_status = PJ_FALSE;

  pj_mutex_lock (PEER_IMPL(p)->lock);

  /// 초기화되지 않았다
	if (PEER_IMPL (p)->state != P2P_PEER_INITED) 
	{
		return -1;
	}

	//실행중?
	if (PEER_IMPL (p)->state == P2P_PEER_RUNNING) {
		
		return PJ_SUCCESS;
	}
	//실행중?
	if (pj_ice_strans_sess_is_complete (PEER_IMPL(p)->ice_strans)) {
		
    return PJ_SUCCESS;
  }

	//for testing...
  rem_ufrag = pj_str ("100");
  rem_passwd = pj_str ("100");
	//rem_ufrag.slen = 0;
	//rem_passwd.slen = 0;

  //decoding
  decode_status = p2p_decode_sd (sd, cand, &cand_count);
  pj_assert (PJ_TRUE == decode_status);

  status = pj_ice_strans_start_ice (PEER_IMPL(p)->ice_strans,  
   				                    &rem_ufrag, 
				                    &rem_passwd,
				                    cand_count,  
				                    cand);      
	pj_assert (PJ_SUCCESS == status);

  pj_mutex_unlock (PEER_IMPL(p)->lock);
   
	PEER_IMPL(p)->usn = usn;

  PEER_IMPL(p)->state = P2P_PEER_RUNNING;

  return PJ_SUCCESS;
}

void p2p_peer_stop (p2p_peer *p) 
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));

	pj_ice_strans_stop_ice (PEER_IMPL(p)->ice_strans);

	PEER_IMPL(p)->usn = 0;
	PEER_IMPL(p)->state = P2P_PEER_STOPED;

	pj_timer_heap_cancel (PEER_IMPL(p)->timer, PEER_IMPL(p)->entry);
}

void p2p_peer_destroy (p2p_peer *p)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));

	pj_ice_strans_destroy (PEER_IMPL(p)->ice_strans);
	pj_mutex_destroy (PEER_IMPL(p)->lock);
	pj_pool_release (PEER_IMPL(p)->pool);

	PEER_IMPL(p)->state = P2P_PEER_DESTROYED;
}

int p2p_peer_get_state (const p2p_peer *p)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));
  return PEER_IMPL(p)->state;
}

pj_status_t p2p_peer_sendto (const p2p_peer *p, 
								const void *msg, 
								unsigned int msg_len)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));
  pj_assert (msg);

	pj_status_t status;
	pj_ice_sess_cand cand;

  if (PEER_IMPL(p)->state != P2P_PEER_RUNNING)
    return -1;

	status = pj_ice_strans_get_def_cand (PEER_IMPL(p)->ice_strans, 1, &cand); 
	pj_assert(status == PJ_SUCCESS);

  return pj_ice_strans_sendto (PEER_IMPL(p)->ice_strans,
                               1, //comp_id
                               msg,
                               msg_len,
								&cand.addr.ipv4,
                               sizeof (cand.addr.ipv4));
}


unsigned p2p_peer_get_usn (const p2p_peer *p)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));
  return PEER_IMPL(p)->usn;
}

pj_status_t p2p_peer_enum_cands (const p2p_peer *p, 
									unsigned *count, 
									pj_ice_sess_cand cand[])
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));

	pj_status_t status;
	status = pj_ice_strans_enum_cands (PEER_IMPL(p)->ice_strans, 1, count, cand);
	pj_assert (status == PJ_SUCCESS);

	return status;
}

pj_ice_cand_type p2p_peer_get_local_connection_type (const p2p_peer *p)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));

	if(P2P_PEER_RUNNING == PEER_IMPL(p)->state)
	{
		if (pj_ice_strans_has_sess (PEER_IMPL(p)->ice_strans)) 
		{
			const pj_ice_sess_check *check = 
				pj_ice_strans_get_valid_pair (PEER_IMPL(p)->ice_strans, 1);
			
			if (check) 
				return check->lcand->type;
		}
	}
}

pj_ice_cand_type p2p_peer_get_remote_connection_type (const p2p_peer *p)
{
	pj_assert (p);
	pj_assert (PEER_IMPL(p));

	if(P2P_PEER_RUNNING == PEER_IMPL(p)->state)
	{
		if (pj_ice_strans_has_sess (PEER_IMPL(p)->ice_strans)) 
		{
			const pj_ice_sess_check *check = 
				pj_ice_strans_get_valid_pair (PEER_IMPL(p)->ice_strans, 1);
			
			if (check) 
				return check->rcand->type;
		}
	}
}

static unsigned calc_cands_size (const pj_ice_sess_cand cand[], unsigned count)
{ 
  unsigned total_size = 0;

  for (unsigned i = 0; i < count; ++i)
  {
    total_size += sizeof (pj_ice_cand_type);
    total_size += sizeof (pj_status_t);   
    total_size += sizeof (pj_uint8_t);          //comp_id 
    total_size += sizeof (pj_uint8_t);          //transport_id
    total_size += sizeof (pj_uint16_t);         //local_pref

    total_size += sizeof (pj_ssize_t);          //foundation     
    total_size += cand[i].foundation.slen;     

    total_size += sizeof (pj_uint32_t);         //prio
    total_size += 6;														//addr
	total_size += 6;														//base addr
	total_size += 6;														//rel addr 
  }
    
  return total_size;
}

//상대방에게 나의 세션정보를 제공해주기위해...
unsigned p2p_peer_get_sd (const p2p_peer *p, pj_uint8_t **p_sd)
{
	pj_assert (PEER_IMPL(p));

  pj_status_t status;
  pj_ice_sess_cand cand[PJ_ICE_MAX_CAND];
  unsigned count = sizeof (cand);

  if (PEER_IMPL(p)->state > P2P_PEER_INITED)
    return 0;

  status = p2p_peer_enum_cands (p, &count, cand);
  pj_assert (status == PJ_SUCCESS);

  return p2p_encode_sd (PEER_IMPL(p)->pool, cand, count, p_sd);
}

unsigned p2p_encode_sd (pj_pool_t *pool,
						const pj_ice_sess_cand cand[],
						unsigned cand_count,
						pj_uint8_t **sd)
{
  pj_assert (pool);

  pj_uint8_t *buf, *start;
  unsigned total = 0;
  
  total = calc_cands_size (cand, cand_count);

	//동적할당을 피하도록 수정할 것이다
  buf = (pj_uint8_t *) pj_pool_zalloc (pool, total + 4);
  pj_assert (buf);

	start = buf;

  PUTVAL32H (buf, 0, cand_count);
  buf += 4;

  for (unsigned i=0; i < cand_count; ++i) 
	{
   
    // candidate type
    pj_memcpy (buf, &cand[i].type, sizeof(pj_ice_cand_type));
    buf += sizeof (pj_ice_cand_type);

    // status
    pj_memcpy (buf, &cand[i].status, sizeof(pj_status_t));
    buf += sizeof (pj_status_t);

    // comp_id
    pj_memcpy (buf, &cand[i].comp_id, sizeof(pj_uint8_t));
    buf += sizeof (pj_uint8_t);

    // transport_id
    pj_memcpy (buf, &cand[i].transport_id, sizeof(pj_uint8_t));
    buf += sizeof (pj_uint8_t);

    // local_pref
    pj_memcpy (buf, &cand[i].local_pref, sizeof(pj_uint16_t));
    buf += sizeof (pj_uint16_t);   

    /* foundation */
    pj_memcpy (buf, &cand[i].foundation.slen, sizeof(pj_ssize_t));
    buf += sizeof (pj_ssize_t);
    
	if (cand[i].foundation.slen > 0) {    
      pj_memcpy (buf, cand[i].foundation.ptr, cand[i].foundation.slen);
      buf += cand[i].foundation.slen;
    }
		
    /* prio */
    pj_memcpy (buf, &cand[i].prio, sizeof (pj_uint32_t));
    buf += sizeof (pj_uint32_t);

    /* addr */
    pj_memcpy (buf, &cand[i].addr.ipv4.sin_port, 2);
    buf += 2;
    pj_memcpy (buf, &cand[i].addr.ipv4.sin_addr, 4);
    buf += 4;

    /* base addr */
    pj_memcpy (buf, &cand[i].base_addr.ipv4.sin_port, 2);
    buf += 2;
    pj_memcpy (buf, &cand[i].base_addr.ipv4.sin_addr, 4);
    buf += 4;

    /* rel addr */
    pj_memcpy (buf, &cand[i].rel_addr.ipv4.sin_port, 2);
    buf += 2;
    pj_memcpy (buf, &cand[i].rel_addr.ipv4.sin_addr, 4);
    buf += 4;
  }
	
	pj_assert ((buf - start) == total + 4);

	if (*sd)
		*sd = start;
  
  return (unsigned)(buf - start);
}

pj_bool_t p2p_decode_sd(const pj_uint8_t *sd,
						pj_ice_sess_cand cand[],
						unsigned *cand_count)
{
  unsigned count = 0;
  pj_uint8_t *buf;

  buf = (pj_uint8_t *)sd;
  
  count = GETVAL32H(buf, 0);

  buf += 4;
 
  for (unsigned i=0; i < count; ++i) {
    //type  
    pj_memcpy (&cand[i].type, buf, sizeof(pj_ice_cand_type));
    buf += sizeof (pj_ice_cand_type);
          
    //status
    pj_memcpy (&cand[i].status, buf, sizeof(pj_status_t));
    buf += sizeof (pj_status_t);      
    
    //comd_id
    pj_memcpy (&cand[i].comp_id, buf, sizeof(pj_uint8_t));
    buf += sizeof (pj_uint8_t);      

    //transport_id
    pj_memcpy (&cand[i].transport_id, buf, sizeof(pj_uint8_t));
    buf += sizeof (pj_uint8_t);  

    //local_pref
    pj_memcpy (&cand[i].local_pref, buf, sizeof(pj_uint16_t));
    buf += sizeof (pj_uint16_t);  

    /* foundation */
    pj_memcpy (&cand[i].foundation.slen, buf, sizeof(pj_ssize_t));
    buf += sizeof (pj_ssize_t);

    if (cand[i].foundation.slen > 0) {
      cand[i].foundation.ptr = (char *)buf;
      buf += cand[i].foundation.slen;     
    }

    //prio
    pj_memcpy (&cand[i].prio, buf, sizeof (pj_uint32_t));
    buf += sizeof (pj_uint32_t);    
        
    /* addr */
    cand[i].addr.ipv4.sin_family = 2;
    cand[i].addr.ipv4.sin_port = GETVAL16N (buf, 0);
    buf += 2;
    cand[i].addr.ipv4.sin_addr.s_addr = GETVAL32N(buf, 0); 
    buf += 4;
        
    /* base addr */
    cand[i].base_addr.ipv4.sin_family = 2;
    cand[i].base_addr.ipv4.sin_port = GETVAL16N (buf, 0);
    buf += 2;
    cand[i].base_addr.ipv4.sin_addr.s_addr = GETVAL32N(buf, 0); 
    buf += 4;


    /* rel addr */
    cand[i].rel_addr.ipv4.sin_family = 2;
    cand[i].rel_addr.ipv4.sin_port = GETVAL16N (buf, 0);
    buf += 2;
    cand[i].rel_addr.ipv4.sin_addr.s_addr = GETVAL32N(buf, 0); 
    buf += 4;
  }

  pj_assert ((buf - (pj_uint8_t*)sd) == calc_cands_size (cand, count) + 4);
  *cand_count = count;

  return PJ_TRUE;
}


void rtt_callback (pj_timer_heap_t *ht, pj_timer_entry *e)
{
	pj_uint32_t magic = RTT_PING_MAGIC;

	p2p_peer *p;
	pj_time_val t, delay;
	
	pj_uint8_t *buf;
	int rc;
	
	p = (p2p_peer *) e->user_data;
	pj_assert (p);
	buf = PEER_IMPL(p)->rtt_buf;
	pj_assert (buf);

	pj_gettimeofday(&t);
	PUTVAL32H(buf, 0, magic);
	PUTVAL32H(buf, 4, PEER_IMPL(p)->usn);
	PUTVAL32H(buf, 8, ++PEER_IMPL(p)->ping_count);
	PUTVAL32H(buf, 12, t.sec);
	PUTVAL32H(buf, 16, t.msec);

	rc = p2p_peer_sendto (p, (void*)buf, 20);
	pj_assert (rc == 0);

	delay.sec		= 1;
    delay.msec	= 0;

	rc = pj_timer_heap_schedule(PEER_IMPL(p)->timer, PEER_IMPL(p)->entry, &delay);
	pj_assert (rc == 0);
}

pj_status_t p2p_peer_start_rtt_est (p2p_peer *p, pj_timer_heap_t *timer)
{
	pj_assert (PEER_IMPL(p));
	pj_time_val delay;
	pj_status_t status;
  
	delay.sec		= 1;
    delay.msec	= 0;

	PEER_IMPL(p)->timer = timer;
	status = pj_timer_heap_schedule(timer, PEER_IMPL(p)->entry, &delay);
	pj_assert (status == 0);

	//pj_srand();
	
	PEER_IMPL(p)->ping_count = 0;

	return status;
}