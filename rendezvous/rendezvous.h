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

#ifndef __NTS_RENDEZVOUS_H__
#define __NTS_RENDEZVOUS_H__

/**
 *	랑데부 콜백
 */
typedef struct rendezvous_cb 
{
	/**
	 * 사용자는 on_result()콜백을 통해 매칭된 피어의 정보를 얻을 수 있습니다.
	 * rendezvous_manager_make_group() 과 rendezvous_manager_join_to_group() 
	 * 의 내부에서 호출합니다. 
	 * @param usn	액티브 피어 usn
	 * @param target_usn 패시브 피어 usn
	 * @param sd	패시브 피어의 session descriptor
	 * @param sd_length	session descriptor 의 길이
	 */
	void (*on_result)	(unsigned int usn, 
						unsigned int target_usn, 
						const unsigned char *sd, 
						unsigned sd_length);
} rendezvous_cb;

/// Forward Declaration
typedef struct rendezvous_manager rendezvous_manager;

/**
 *	랑데부 관리 객체를 생성한다. 캐주얼게임이라면 게임방별로 1개씩 생성한다.
 *
 *  @param cb 콜백
 *  @param p_manager 관리객체 리턴받기 위한 포인터
 *  @return 성공이면 0
 */
int rendezvous_manager_create (unsigned, rendezvous_cb cb, rendezvous_manager **p_manager); 

/**
 *	세션디스크립터를 추가한다.
 *
 *  @param mamanger 관리객체
 *  @param usn 세션디스크립터의 소유자 usn
 *  @param sd 세션디스크립터
 *  @param sd_length 세션디스크립터 길이
 *  @return 성공이면 0
 */
int rendezvous_manager_add_sd (rendezvous_manager *manager, 
											unsigned int usn,
											const unsigned char *sd, 
											unsigned sd_length);

/**
 *	세션디스크립터를 삭제한다.
 *
 *  @param mamanger 관리객체
 *  @param usn 삭제할 세션디스크립터의 소유자 usn
 */
void rendezvous_manager_del_sd (rendezvous_manager *manager,unsigned int usn);

/**
 *	세션그룹을 생성한다.
 *
 *  @param mamanger 관리객체
 *  @return 성공이면 P2P_TRUE
 */
int rendezvous_manager_make_group (rendezvous_manager *manager);

/**
 *	세션그룹에 새로운 PEER를 추가한다.
 *
 *  @param mamanger 관리객체
 *  @param usn 세션디스크립터의 소유자 usn
 *  @param sd 세션디스크립터
 *  @param sd_length 세션디스크립터 길이
 *  @return 성공이면 P2P_TRUE
 */
int rendezvous_manager_join_to_group (rendezvous_manager *manager, 
																unsigned int usn,		
																unsigned char *sd, 
																unsigned sd_length);

/**
 *	세션그룹을 초기화한다.
 *
 *  @param mamanger 관리객체
 */
void rendezvous_manager_reset_group (rendezvous_manager *manager);

/**
 *  추가된 세션디스크립터의 갯수를 리턴한다.
 *
 *  @param mamanger 관리객체
 *  @return 세션디스크립터의 갯수
 */
unsigned rendezvous_manager_get_sd_count (const rendezvous_manager *manager);

unsigned rendezvous_manager_capacity (const rendezvous_manager *);
/**
 *
 *  @param mamanger 관리객체
 *  @return 여부
 */
int rendezvous_manager_is_full (const rendezvous_manager *manager);

/**
 *  관리객체를 제거한다.
 *  @param mamanger 관리객체
 */
void rendezvous_manager_destroy (rendezvous_manager *manager);

#endif