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
 * ���̺귯������ ȣ��Ǵ� �ݹ��� �����ϴ� ����ü��.
 */
typedef struct p2p_transport_cb 
{
	/**
	 * P2P ���̺귯���� �ʱ�ȭ�� �Ϸ�Ǹ� ȣ��ȴ�.
	 * 
	 * @param status		�Ϸ���°�.
	 * @return				�����̸�, 0 �̴�.
	 */
	void (*on_create) (p2p_status_t status);

	/**
	 * �Ǿ �۽��� �����Ͱ� ���ŵǸ� ȣ��ȴ�.
	 *
	 * @param usn			�۽��� �Ǿ��� usn.
	 * @param pkt			��Ŷ.
	 * @param pkt_length	��Ŷ ����.
	 */
	void (*on_rx_data) (p2p_uint32_t usn, 
						void *pkt, 
						size_t pkt_length);

	/**
	 * �Ǿ�� ���� ���� �����ϸ� ȣ��ȴ�.
	 * �ش� �Ǿ���� Round-trip Time
	 * 
	 * @param usn	�Ǿ��� usn.
	 * @param msec	�ɸ��ð�(�и�������).
	 */
	void (*on_rtt_refresh) (p2p_uint32_t usn, 
							unsigned msec);

	/** 
	 * P2P ������ �Ϸ�Ǿ����� ȣ��ȴ�.
	 *
	 * �ƹ��� �ĺ����� ȣ��� �� �ִ�.
	 *
	 * @param	usn			�Ǿ��� usn.
	 * @param status		�Ϸ� ���°��̸�, 0�̸� ����.
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
 * P2P�� �����ϱ� ���� �۾��� �Ѵ�
 * 
 * @param	max_peers		���ÿ� ���ᰡ���� �ִ� �Ǿ� ��.
 * @param	stun_ip			STUN IP.
 * @param	stun_port		STUN port.
 * @param	turn_ip			TURN IP.
 * @param	turn_port		TURN port.
 * @param	is_rtt_check	RTT Check ����.
 * @param	async_count   proactor async count.
 * @param	cb				    p2p callback
 * @return �����̸� 0
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
 * �Ǿ���� ���ǿ����� �õ��Ѵ�
 * 
 * @param usn		    �������� usn
 * @param sd			  ���ǵ�ũ����
 * @param sd_length ���ǵ�ũ������ ����
 * @return �����̸� 0
 */
int p2p_manager_make_session(p2p_uint32_t		usn,		
							 const p2p_uint8_t	*sd,
							 unsigned			sd_length);

/**
 * �Ǿ���� ���ǿ����� �����Ѵ�
 * 
 * @param usn	�������� usn
 */
void p2p_manager_break_session (p2p_uint32_t usn);

/**
 * �۽��Ѵ�
 * 
 * @param usn		���Ŵ���� usn
 * @param pkt		������ ��Ŷ
 * @param pkt_length ��Ŷ ����
 * @return			�����̸� 0
 */
int p2p_manager_sendto(p2p_uint32_t	usn,		
					   const void	*pkt,
					   unsigned		pkt_length);		
  
/**
 * �ڽ��� ���ǵ�ũ���͸� ��ȸ�Ѵ�.
 * janet-p2p�� ���������� �Ǿ ���� ������ �����Ѵ�.
 * �ʱ�ȭ�� �Ϸ�� �� �Ŀ� ȣ�� �Ͽ��� �Ѵ�.
 *
 * @param p_sd ���ǵ�ũ���Ͱ� ����� ����
 * @return �����̸� local sd �� ũ��, �����ϸ� 0
 */
unsigned p2p_manager_get_local_sd (p2p_uint8_t **p_sd);

/**
 * ���̺귯���� ����� �޸𸮸� ��ȯ�ϸ�, ��� ����� �Ǿ���� ������ �����Ѵ�.
 */
void p2p_manager_destroy ();

/**
 * NAT Type Check
 */
p2p_status_t p2p_stun_detect_nat_type(p2p_manager_stun_nat_detect_cb *cb);

#endif