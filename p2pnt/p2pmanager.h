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

#ifndef __P2PMANAGER_H__
#define __P2PMANAGER_H__

/**
 * @file p2pmanager.h
 * @brief P2P Manager.
 */

#include "types.h"

typedef enum p2p_conn_type
{
	p2p_conn_type_HOST,
	p2p_conn_type_SRFLX,
	p2p_conn_type_PRELX,
	p2p_conn_type_RELAYED,
} p2p_conn_type;

/**
 * 라이브러리에서 호출되는 콜백을 저장하는 구조체다.
 */
typedef struct p2p_transport_cb 
{
	/**
	 * P2P 라이브러리의 초기화가 완료되면 호출된다.
	 * 
	 * @param status		완료상태값.
	 * @return				성공이면, 0 이다.
	 */
	void (*on_create) (p2p_status_t status);

	/**
	 * 피어가 송신한 데이터가 수신되면 호출된다.
	 *
	 * @param usn			송신한 피어의 usn.
	 * @param pkt			패킷.
	 * @param pkt_length	패킷 길이.
	 */
	void (*on_rx_data) (p2p_uint32_t usn, 
						void *pkt, 
						size_t pkt_length);

	/**
	 * 피어에게 보낸 핑이 도착하면 호출된다.
	 * 해당 피어와의 Round-trip Time
	 * 
	 * @param usn	피어의 usn.
	 * @param msec	걸린시간(밀리세컨드).
	 */
	void (*on_rtt_refresh) (p2p_uint32_t usn, 
							unsigned msec);

	/** 
	 * P2P 연결이 완료되었을때 호출된다.
	 *
	 * 아무런 후보없이 호출될 수 있다.
	 *
	 * @param	usn			피어의 usn.
	 * @param status		완료 상태값이며, 0이면 성공.
	 */
	void (*on_ice_complete)(p2p_uint32_t usn, 
							p2p_conn_type local_type, 
							p2p_conn_type remote_type,
							p2p_status_t status);

} p2p_transport_cb;

typedef enum p2p_stun_nat_type
{
    /**
     * NAT type is unknown because the detection has not been performed.
     */
    P2P_STUN_NAT_TYPE_UNKNOWN,

    /**
     * NAT type is unknown because there is failure in the detection
     * process, possibly because server does not support RFC 3489.
     */
    P2P_STUN_NAT_TYPE_ERR_UNKNOWN,

    /**
     * This specifies that the client has open access to Internet (or
     * at least, its behind a firewall that behaves like a full-cone NAT,
     * but without the translation)
     */
    P2P_STUN_NAT_TYPE_OPEN,

    /**
     * This specifies that communication with server has failed, probably
     * because UDP packets are blocked.
     */
    P2P_STUN_NAT_TYPE_BLOCKED,

    /**
     * Firewall that allows UDP out, and responses have to come back to
     * the source of the request (like a symmetric NAT, but no
     * translation.
     */
    P2P_STUN_NAT_TYPE_SYMMETRIC_UDP,

    /**
     * A full cone NAT is one where all requests from the same internal 
     * IP address and port are mapped to the same external IP address and
     * port.  Furthermore, any external host can send a packet to the 
     * internal host, by sending a packet to the mapped external address.
     */
    P2P_STUN_NAT_TYPE_FULL_CONE,

    /**
     * A symmetric NAT is one where all requests from the same internal 
     * IP address and port, to a specific destination IP address and port,
     * are mapped to the same external IP address and port.  If the same 
     * host sends a packet with the same source address and port, but to 
     * a different destination, a different mapping is used.  Furthermore,
     * only the external host that receives a packet can send a UDP packet
     * back to the internal host.
     */
    P2P_STUN_NAT_TYPE_SYMMETRIC,

    /**
     * A restricted cone NAT is one where all requests from the same 
     * internal IP address and port are mapped to the same external IP 
     * address and port.  Unlike a full cone NAT, an external host (with 
     * IP address X) can send a packet to the internal host only if the 
     * internal host had previously sent a packet to IP address X.
     */
    P2P_STUN_NAT_TYPE_RESTRICTED,

    /**
     * A port restricted cone NAT is like a restricted cone NAT, but the 
     * restriction includes port numbers. Specifically, an external host 
     * can send a packet, with source IP address X and source port P, 
     * to the internal host only if the internal host had previously sent
     * a packet to IP address X and port P.
     */
    P2P_STUN_NAT_TYPE_PORT_RESTRICTED

} p2p_stun_nat_type;

typedef void p2p_manager_stun_nat_detect_cb (p2p_stun_nat_type type, const char *natname);

int p2p_init();
void p2p_shutdown();

/**
 * P2P를 수행하기 위한 작업을 한다
 * 
 * @param	max_peers		동시에 연결가능한 최대 피어 수.
 * @param	stun_ip			STUN IP.
 * @param	stun_port		STUN port.
 * @param	turn_ip			TURN IP.
 * @param	turn_port		TURN port.
 * @param	is_rtt_check	RTT Check 여부.
 * @param	async_count   proactor async count.
 * @param	cb				    p2p callback
 * @return 성공이면 0
 */
int p2p_manager_create(unsigned                     max_peers,    
					   const char					*stun_ip,			
					   p2p_uint16_t					stun_port,		
					   const char					*turn_ip,			   						 
					   p2p_uint16_t					turn_port,
					   p2p_bool_t					is_rtt_check,
					   unsigned						async_count,
					   p2p_transport_cb	cb);					

/**
 * 피어와의 세션연결을 시도한다
 * 
 * @param usn		    연결대상의 usn
 * @param sd			  세션디스크립터
 * @param sd_length 세션디스크립터의 길이
 * @return 성공이면 0
 */
int p2p_manager_make_session(p2p_uint32_t		usn,		
							 const p2p_uint8_t	*sd,
							 unsigned			sd_length);

/**
 * 피어와의 세션연결을 종료한다
 * 
 * @param usn	연결대상의 usn
 */
void p2p_manager_break_session (p2p_uint32_t usn);

/**
 * 송신한다
 * 
 * @param usn		수신대상의 usn
 * @param pkt		보내는 패킷
 * @param pkt_length 패킷 길이
 * @return			성공이면 0
 */
int p2p_manager_sendto(p2p_uint32_t	usn,		
					   const void	*pkt,
					   unsigned		pkt_length);		
  
/**
 * 자신의 세션디스크립터를 조회한다.
 * janet-p2p는 내부적으로 피어에 대한 정보를 관리한다.
 * 초기화가 완료된 이 후에 호출 하여야 한다.
 *
 * @param p_sd 세션디스크립터가 저장될 변수
 * @return 성공이면 local sd 의 크기, 실패하면 0
 */
unsigned p2p_manager_get_local_sd (p2p_uint8_t **p_sd);

/**
 * 라이브러리가 사용한 메모리를 반환하며, 모든 연결된 피어와의 세션을 종료한다.
 */
void p2p_manager_destroy ();

/**
 * NAT Type Check
 */
p2p_status_t p2p_stun_detect_nat_type(p2p_manager_stun_nat_detect_cb *cb);

#endif