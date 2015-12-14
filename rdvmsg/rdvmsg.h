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

#ifndef __RDVMSG_H__
#define __RDVMSG_H__

#include "config.h"
#include "../p2pnt/types.h"

typedef enum rdv_msg_type
{
	RDV_LOGIN_REQUEST	= 0x0002,
	RDV_LOGIN_RESPONSE	= 0x0102,
	RDV_NEWUSER			= 0x0003
} rdv_msg_type;

typedef enum rdv_msg_attr_type
{
  RDV_ATTR_USN = 0x0001,
  RDV_ATTR_ID  = 0x0002,
  RDV_ATTR_SD  = 0x0003,
  RDV_ATTR_END_ATTR
} rdv_msg_attr_type;

typedef struct rdv_msg_hdr
{  
  p2p_uint16_t	type;
  p2p_uint16_t	length;
} rdv_msg_hdr;

typedef struct rdv_attr_hdr
{
  p2p_uint16_t	type;
  p2p_uint16_t	length;
} rdv_attr_hdr;

typedef struct rdv_uint_attr
{  
  rdv_attr_hdr	hdr;
  p2p_uint32_t	value;
} rdv_uint_attr;

typedef struct rdv_string_attr
{  
  rdv_attr_hdr	hdr;
  char			*value;
} rdv_string_attr;

typedef struct rdv_binary_attr
{  
  rdv_attr_hdr hdr;
  unsigned length;
  p2p_uint8_t *data;
} rdv_binary_attr;

typedef struct rdv_msg
{
  rdv_msg_hdr hdr;

  unsigned attr_count;
  rdv_attr_hdr *attr[RDV_MAX_ATTR];
} rdv_msg;

int rdv_msg_create (unsigned msg_type, rdv_msg **p_msg);

int rdv_msg_add_attr (rdv_msg *msg, rdv_attr_hdr *attr);

int rdv_uint_attr_create (int attr_type, p2p_uint32_t value, rdv_uint_attr **p_attr);

int rdv_msg_add_uint_attr (rdv_msg *msg, int attr_type, p2p_uint32_t value);
												 
int rdv_string_attr_init (rdv_string_attr *attr, int attr_type, const char *value);

int rdv_string_attr_create (int attr_type, const char *str, rdv_string_attr **p_attr);

int rdv_msg_add_string_attr (rdv_msg *msg, int attr_type, const char *value);

int rdv_binary_attr_init (rdv_binary_attr *attr,int attr_type,const p2p_uint8_t *data,unsigned length);

int rdv_binary_attr_create(int attr_type,const p2p_uint8_t *data,unsigned length,rdv_binary_attr **p_attr);

int rdv_msg_add_binary_attr(rdv_msg *msg,int attr_type,const p2p_uint8_t *data,unsigned length);

rdv_attr_hdr * rdv_msg_find_attr (const rdv_msg *msg, int attr_type, unsigned index);

int rdv_msg_encode (rdv_msg *msg, p2p_uint8_t *pkt_buf, size_t buf_size, size_t *p_msg_len);

int rdv_msg_decode (const p2p_uint8_t *pdu, size_t pdu_len,rdv_msg *msg, size_t *p_parsed_len, rdv_msg **p_response);

void rdv_msg_destroy (rdv_msg *msg);


#endif