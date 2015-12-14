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
 *	������ �ݹ�
 */
typedef struct rendezvous_cb 
{
	/**
	 * ����ڴ� on_result()�ݹ��� ���� ��Ī�� �Ǿ��� ������ ���� �� �ֽ��ϴ�.
	 * rendezvous_manager_make_group() �� rendezvous_manager_join_to_group() 
	 * �� ���ο��� ȣ���մϴ�. 
	 * @param usn	��Ƽ�� �Ǿ� usn
	 * @param target_usn �нú� �Ǿ� usn
	 * @param sd	�нú� �Ǿ��� session descriptor
	 * @param sd_length	session descriptor �� ����
	 */
	void (*on_result)	(unsigned int usn, 
						unsigned int target_usn, 
						const unsigned char *sd, 
						unsigned sd_length);
} rendezvous_cb;

/// Forward Declaration
typedef struct rendezvous_manager rendezvous_manager;

/**
 *	������ ���� ��ü�� �����Ѵ�. ĳ�־�����̶�� ���ӹ溰�� 1���� �����Ѵ�.
 *
 *  @param cb �ݹ�
 *  @param p_manager ������ü ���Ϲޱ� ���� ������
 *  @return �����̸� 0
 */
int rendezvous_manager_create (unsigned, rendezvous_cb cb, rendezvous_manager **p_manager); 

/**
 *	���ǵ�ũ���͸� �߰��Ѵ�.
 *
 *  @param mamanger ������ü
 *  @param usn ���ǵ�ũ������ ������ usn
 *  @param sd ���ǵ�ũ����
 *  @param sd_length ���ǵ�ũ���� ����
 *  @return �����̸� 0
 */
int rendezvous_manager_add_sd (rendezvous_manager *manager, 
											unsigned int usn,
											const unsigned char *sd, 
											unsigned sd_length);

/**
 *	���ǵ�ũ���͸� �����Ѵ�.
 *
 *  @param mamanger ������ü
 *  @param usn ������ ���ǵ�ũ������ ������ usn
 */
void rendezvous_manager_del_sd (rendezvous_manager *manager,unsigned int usn);

/**
 *	���Ǳ׷��� �����Ѵ�.
 *
 *  @param mamanger ������ü
 *  @return �����̸� P2P_TRUE
 */
int rendezvous_manager_make_group (rendezvous_manager *manager);

/**
 *	���Ǳ׷쿡 ���ο� PEER�� �߰��Ѵ�.
 *
 *  @param mamanger ������ü
 *  @param usn ���ǵ�ũ������ ������ usn
 *  @param sd ���ǵ�ũ����
 *  @param sd_length ���ǵ�ũ���� ����
 *  @return �����̸� P2P_TRUE
 */
int rendezvous_manager_join_to_group (rendezvous_manager *manager, 
																unsigned int usn,		
																unsigned char *sd, 
																unsigned sd_length);

/**
 *	���Ǳ׷��� �ʱ�ȭ�Ѵ�.
 *
 *  @param mamanger ������ü
 */
void rendezvous_manager_reset_group (rendezvous_manager *manager);

/**
 *  �߰��� ���ǵ�ũ������ ������ �����Ѵ�.
 *
 *  @param mamanger ������ü
 *  @return ���ǵ�ũ������ ����
 */
unsigned rendezvous_manager_get_sd_count (const rendezvous_manager *manager);

unsigned rendezvous_manager_capacity (const rendezvous_manager *);
/**
 *
 *  @param mamanger ������ü
 *  @return ����
 */
int rendezvous_manager_is_full (const rendezvous_manager *manager);

/**
 *  ������ü�� �����Ѵ�.
 *  @param mamanger ������ü
 */
void rendezvous_manager_destroy (rendezvous_manager *manager);

#endif