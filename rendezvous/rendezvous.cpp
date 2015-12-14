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

#include "rendezvous.h"
#include <stdlib.h>
#include <assert.h>
#include <winsock2.h>

typedef struct rendezvous_user 
{
	unsigned int usn;

	struct sess_desc_
	{
		unsigned int		idx;
		unsigned char	*sd;
		unsigned			sd_length;
		int						selected;
	} **sess_desc;

	unsigned max_sess_desc;
	unsigned cur_sess_desc_count;

} rendezvous_user;

typedef struct rendezvous_manager
{
	rendezvous_user **users;
	
	unsigned max_user;
	unsigned cur_user_count;
	
	int is_group_made;

	rendezvous_cb cb;
} rendezvous_manager;

/* return sd currently not used in user */

static void get_free_slot_of_user (	rendezvous_user *user, 
														unsigned char **p_sd, 
														unsigned *p_sd_length);

/*
 * 이 함수는 인자로 전달된 세션디스크립터를 디코딩하여 
 * rendezvous_user를 초기화하는 함수입니다.
 */
static void init_user (rendezvous_user *user, 
								unsigned int usn,
								const unsigned char *sd, 
								unsigned sd_length);

/* 이 함수는 rendezvous_user를 0으로 초기화합니다.
 */
static void reset_user (rendezvous_user *user);


//클라이언트를 조회한다
static rendezvous_user * find_user_from_manager_by_usn (	rendezvous_manager *manager, 
																		unsigned int usn);

//랑데부매니저의 유저배열에서 사용되지 않은 객체를 리턴한다
static rendezvous_user * get_free_user (rendezvous_manager *manager);

static unsigned short GETVAL16H(const unsigned char *buf, unsigned pos)
{
    return (unsigned short) ((buf[pos + 0] << 8) | (buf[pos + 1] << 0));
}

static unsigned short GETVAL16N(const unsigned char *buf, unsigned pos)
{
    return htons(GETVAL16H(buf,pos));
}

static void PUTVAL16H(unsigned char *buf, unsigned pos, unsigned short hval)
{
    buf[pos+0] = (unsigned char) ((hval & 0xFF00) >> 8);
    buf[pos+1] = (unsigned char) ((hval & 0x00FF) >> 0);
}

static unsigned int GETVAL32H(const unsigned char *buf, unsigned pos)
{
    return (unsigned int) ((buf[pos + 0] << 24UL) | \
						  (buf[pos + 1] << 16UL) | \
						  (buf[pos + 2] <<  8UL) | \
						  (buf[pos + 3] <<  0UL));
}

static unsigned int GETVAL32N(const unsigned char *buf, unsigned pos)
{
    return htonl(GETVAL32H(buf,pos));
}

static void PUTVAL32H(unsigned char *buf, unsigned pos, unsigned int hval)
{
    buf[pos+0] = (unsigned char) ((hval & 0xFF000000UL) >> 24);
    buf[pos+1] = (unsigned char) ((hval & 0x00FF0000UL) >> 16);
    buf[pos+2] = (unsigned char) ((hval & 0x0000FF00UL) >>  8);
    buf[pos+3] = (unsigned char) ((hval & 0x000000FFUL) >>  0);
}

int rendezvous_manager_create (unsigned max_user,
												rendezvous_cb cb,
												rendezvous_manager **p_manager)
{
	rendezvous_manager *manager;
	manager = (rendezvous_manager *) malloc (sizeof (rendezvous_manager));

	manager->users = (rendezvous_user **) malloc (max_user * sizeof (rendezvous_user*));
	manager->max_user = max_user;
	
	for (unsigned i = 0; i < manager->max_user; ++i) 
	{
		manager->users[i] = (rendezvous_user *) malloc (sizeof (rendezvous_user));
		rendezvous_user *user = manager->users[i];
		
		user->max_sess_desc = manager->max_user -1;

		user->sess_desc = 
			(rendezvous_user::sess_desc_ **) 
			malloc (user->max_sess_desc * sizeof (rendezvous_user::sess_desc_*));

		user->usn = 0;
		
		user->cur_sess_desc_count = 0;

		for (unsigned j = 0; j < user->max_sess_desc; ++j) 
		{
			user->sess_desc[j] = 
				(rendezvous_user::sess_desc_ *) malloc (sizeof (rendezvous_user::sess_desc_));
			user->sess_desc[j]->idx = 0;
			user->sess_desc[j]->sd = 0;
			user->sess_desc[j]->sd_length = 0;
			user->sess_desc[j]->selected = 0;
		}
	}

	manager->cur_user_count = 0;
	manager->is_group_made = 0;

	manager->cb = cb;

	*p_manager = manager;

	return 0;
}


void rendezvous_manager_destroy (rendezvous_manager *manager)
{
	if (0!= manager) 
	{
		for (unsigned i = 0; i < manager->max_user; ++i) 
		{
			rendezvous_user *user = manager->users[i];
			for (unsigned j = 0; i < user->max_sess_desc; ++i) 
			{
				free (user->sess_desc[j]);
				user->sess_desc[j] = 0;
			}
			free (user->sess_desc);

			free (user);
			manager->users[i] = 0;
		}
		free (manager->users);
		free (manager);
	}
}

int rendezvous_manager_add_sd  (rendezvous_manager *manager,
												   unsigned int usn,      
												   const unsigned char *sd,          
												   unsigned sd_length)
{
	if (0 != manager) 
	{
		rendezvous_user *user = 0;

		//pj_assert (manager);
		user = get_free_user (manager);
		if (0 != user)
		{
			init_user (user, usn, sd, sd_length);
			return ++manager->cur_user_count;	
		}

		return -1;
	}

	return 0;
}

void rendezvous_manager_del_sd (rendezvous_manager *manager, unsigned int usn)
{
	if (0 != manager) 
	{
		rendezvous_user *user = 0;
		user = find_user_from_manager_by_usn (manager, usn);
		if (0 != user)
		{
			reset_user (user);
			--manager->cur_user_count;
		}
	}
}

// 호출되려면 user count >= 2 의 조건을 만족해야 한다.
// 이미 결과가 도출되어진 상태라면, 이 호출은 새로운 유저가 세션그룹에 참여하기 
// 위한 것이어야 한다. 
// 이 함수를 사용하는 프로그래머는 이 점을 주의해야 한다.
int rendezvous_manager_make_group (rendezvous_manager *manager)
{

	if (rendezvous_manager_get_sd_count(manager) < 2) {
		return -1;
	}

	for (unsigned i = 0; i < manager->max_user; ++i) 
	{
		rendezvous_user *user1 = manager->users[i];
			
		if(0 == user1->usn) continue;

		for (unsigned j = i+1; j < manager->max_user; ++j)
		{
			rendezvous_user *user2 = manager->users[j];

			if (user2->usn != 0) //another user1?
			{
				unsigned char *user1_sd, *user2_sd;
				unsigned	user1_sd_length, user2_sd_length;

				unsigned int user1_idx, user2_idx;

				get_free_slot_of_user (user1, &user1_sd, &user1_sd_length);
				//pj_assert (user1_sd && user1_sd_length > 0);

				get_free_slot_of_user (user2, &user2_sd, &user2_sd_length);
				//pj_assert (user2_sd && user2_sd_length > 0);

				//idx 교환
				user1_idx = GETVAL32H (user1_sd, 0);
				user2_idx = GETVAL32H (user2_sd, 0);
				PUTVAL32H (user2_sd, 0, user1_idx);
				PUTVAL32H (user1_sd, 0, user2_idx);			
						
				if (manager->cb.on_result) {
					(*manager->cb.on_result) (	user1->usn, 
																user2->usn, 
																user2_sd, 
																user2_sd_length);

					(*manager->cb.on_result)(	user2->usn, 
																user1->usn, 
																user1_sd, 
																user1_sd_length);
				
				}
			}
		}
	}

	manager->is_group_made = 1;

	return 0;
}

int rendezvous_manager_join_to_group (rendezvous_manager *manager,
																unsigned int usn,
																unsigned char *sd,
																unsigned sd_length)
{	
	//그룹이 존재하는가?
	if (0 == manager->is_group_made) 
	{
		return -1;
	}
		
	//추가할 수 있는가?
	if (0 == rendezvous_manager_is_full(manager)) 
	{
		return -2;
	}

	// 이미 세션그룹이 만들어진 상태이기 때문에 가정에 주의한다.
	// 1. 전체유저의 모든 sd들은 교환되어져 있다.
	// 2. sd idx는 서로 교환되어 있다.
	// 주의하라! 이와 같이 세션그룹이 있는 상태에서 
	// rendezvous_manager_make_result의 재호출은, 새로운 세션을 그룹에 
	// 추가하는 것이 아니라면 에러이다. 
	// 새로운 세션을 그룹에 추가하는 것인지 체크하고, 아니라면 그냥 리턴한다.
		
	if (usn != 0 && sd && sd_length > 0)
	{
		unsigned i;
		int status;

		//add new_user to session group
		status = rendezvous_manager_add_sd (manager, usn, sd, sd_length); 
		//pj_assert (status == 0);

		//////////////////////////////////////
		/// 새유저를 추가한 result를 리턴한다
		rendezvous_user *new_user = find_user_from_manager_by_usn (manager, usn);

		for (i = 0; i < manager->max_user; ++i)
		{
			rendezvous_user *existing_user = manager->users[i];

			if(existing_user->usn != 0 && new_user->usn != existing_user->usn)
			{
				unsigned char *sd_of_new_user, *existing_user_sd;
				unsigned sd_length_of_new_user, sd_length_of_existing_user;

				unsigned int new_user_idx, existing_user_idx;

				//기존유저에게 전달할 sd를 조회한다.
				get_free_slot_of_user (new_user, &sd_of_new_user, &sd_length_of_new_user);
				//pj_assert (sd_of_new_user && sd_length_of_new_user > 0);
					
				//새 유저에게 전달할 sd를 조회한다.
				get_free_slot_of_user (existing_user, &existing_user_sd, &sd_length_of_existing_user);
				//pj_assert (existing_user_sd && sd_length_of_existing_user > 0);

				//idx 교환
				new_user_idx = GETVAL32H (sd_of_new_user, 0);
				existing_user_idx = GETVAL32H (existing_user_sd, 0);
				PUTVAL32H (existing_user_sd, 0, new_user_idx);
				PUTVAL32H (sd_of_new_user, 0, existing_user_idx);

				if (manager->cb.on_result) {
					(*manager->cb.on_result)(	new_user->usn, 
																existing_user->usn, 
																existing_user_sd, 
																sd_length_of_existing_user);

					(*manager->cb.on_result)(	existing_user->usn, 
																new_user->usn, 
																sd_of_new_user, 
																sd_length_of_new_user);
				}	
			}
		}
	}

	return 0;
}


void rendezvous_manager_reset_group (rendezvous_manager *manager)
{
	for (unsigned i = 0; i < manager->max_user; ++i) 
	{
		rendezvous_user *user = manager->users[i];

		if (0 != user->usn)
		{
			//유저의 세션디스크립터들을 초기상태로 돌려놓습니다.
			for (unsigned j = 0; j < user->max_sess_desc; ++j) 
			{
				if (0 != user->sess_desc[j]->idx) {

					//restoring idx
					PUTVAL32H (user->sess_desc[j]->sd, 0, user->sess_desc[j]->idx);
				}

				user->sess_desc[j]->selected = 0;
			}

			user->usn = 0;
		}
	}

	manager->is_group_made = 0;
}

unsigned rendezvous_manager_get_sd_count (const rendezvous_manager *manager)
{
	return manager->cur_user_count;
}

unsigned rendezvous_manager_capacity (const rendezvous_manager *manager)
{
	return manager->max_user;
}

int rendezvous_manager_is_full (const rendezvous_manager *manager)
{
	if (manager->cur_user_count == manager->max_user) {
		return 0;
	}

	return -1;
}


rendezvous_user * get_free_user (rendezvous_manager *manager)
{
	for (unsigned i = 0; i < manager->max_user; ++i) 
	{
		if (0 == manager->users[i]->usn) 
		{
			return manager->users[i];
		}
	}

	return 0;
}

rendezvous_user * find_user_from_manager_by_usn (rendezvous_manager *manager, 
																					unsigned int usn)
{

	for (unsigned i = 0; i < manager->max_user; ++i) 
	{
		if (usn == manager->users[i]->usn) 
		{
			return manager->users[i];
		}
	}

	return 0;
}


void get_free_slot_of_user (	rendezvous_user *user,
												unsigned char **p_sd, 
												unsigned *p_sd_length)
{
	for (unsigned i = 0; i < user->max_sess_desc; ++i) 
	{
		if (0 == user->sess_desc[i]->selected) 
		{
			*p_sd = user->sess_desc[i]->sd;
			*p_sd_length = user->sess_desc[i]->sd_length;

			user->sess_desc[i]->selected = 1;
			return;
		}
	}

	if (*p_sd) 
	{
		*p_sd = NULL;
		*p_sd_length = 0;
	}
}

static void init_user (rendezvous_user *user, 
								 unsigned int usn,
								 const unsigned char *sd, 
								 unsigned sd_length)
{
	unsigned char *buf = (unsigned char *)sd;
	unsigned pos =0;

	//pj_assert (user);

	//초기화해준다
	if (user->cur_sess_desc_count > 0) {
		reset_user (user);
	}

	for (unsigned i = 0; i < user->max_sess_desc; ++i) 
	{
		unsigned int length;

		//	+----------+----+----+
		//	|	sd's length  |  idx  | sd		|
		//	+----------+----+----+
		//실제 sd의 길이를 얻는다.
		length = GETVAL32H (buf, 0);
		user->sess_desc[i]->sd_length = length;
		buf += 4;

		//idx를 얻는다.
		user->sess_desc[i]->idx = GETVAL32H (buf, 0);
		//buf += 4;

		user->sess_desc[i]->sd = buf;
		buf += length;
		
		user->sess_desc[i]->selected = 0;
		
		++user->cur_sess_desc_count;
	}

	user->usn = usn;
	//pj_assert (sd_length == (buf - sd));
}

void reset_user (rendezvous_user *user)
{
	for (unsigned i = 0; i < user->max_sess_desc; ++i) 
	{
		if (user->sess_desc[i]->idx) 
		{
			user->sess_desc[i]->idx = 0;
			user->sess_desc[i]->sd = 0;
			user->sess_desc[i]->sd_length = 0;
			
			user->sess_desc[i]->selected = 0;
		}
	}

	user->cur_sess_desc_count = 0;
}

