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

#ifndef __P2P_PEER_H__
#define __P2P_PEER_H__

/**
 * @file p2p_peer.h
 * @brief 피어 관리.
 */

#include <pjnath.h>
#include "types.h"

#define RTT_PING_MAGIC 0xf7f70c1c



typedef struct p2p_peer_impl p2p_peer_impl;

typedef struct p2p_peer 
{
	PJ_DECL_LIST_MEMBER (p2p_peer);

	p2p_peer_impl	*impl;
	pj_uint32_t		idx;
} p2p_peer;

enum {
	P2P_PEER_CREATED =1,
	P2P_PEER_INITED,
	P2P_PEER_RUNNING,
	P2P_PEER_STOPED ,
	P2P_PEER_DESTROYED,
};

pj_status_t p2p_peer_create (pj_ice_strans_cfg *ice_cfg,		//ice config
							 const pj_ice_strans_cb ice_cb,		//callback object
							 pj_uint16_t s_port,				//starting point to bind port
							 p2p_peer *p);						//psess instance

pj_status_t p2p_peer_init (p2p_peer *p);

pj_status_t p2p_peer_start (p2p_peer *p, 
							pj_uint32_t usn, 
							const pj_uint8_t *sd, 
							unsigned sd_len);
 
void p2p_peer_stop (p2p_peer *p);

void p2p_peer_destroy (p2p_peer *p);

int p2p_peer_get_state (const p2p_peer *p);

pj_status_t p2p_peer_sendto (const p2p_peer *p, 
							 const void *msg, 
							 unsigned msg_len);

unsigned p2p_peer_get_usn (const p2p_peer *p);

pj_status_t p2p_peer_enum_cands (const p2p_peer *p, 
								 unsigned *count, 
								 pj_ice_sess_cand cand[]);

pj_ice_cand_type p2p_peer_get_local_connection_type (const p2p_peer *p);
pj_ice_cand_type p2p_peer_get_remote_connection_type (const p2p_peer *p);

//상대방에게 나의 세션정보를 제공해주기위해...
unsigned p2p_peer_get_sd (const p2p_peer *p, pj_uint8_t **p_sd);

unsigned p2p_encode_sd (pj_pool_t *pool,
						const pj_ice_sess_cand cand[],
						unsigned cand_count,
						pj_uint8_t **sd);

pj_bool_t p2p_decode_sd (const pj_uint8_t *sd,
						 pj_ice_sess_cand cand[],
						 unsigned *cand_count);

pj_status_t p2p_peer_start_rtt_est (p2p_peer *p, 
									pj_timer_heap_t *timer);

#endif