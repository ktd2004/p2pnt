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

#include "rdvmsg.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

p2p_uint16_t GETVAL16H(const p2p_uint8_t *buf, unsigned pos)
{
    return (p2p_uint16_t) ((buf[pos + 0] << 8) | (buf[pos + 1] << 0));
}

p2p_uint16_t GETVAL16N(const p2p_uint8_t *buf, unsigned pos)
{
    return htons(GETVAL16H(buf,pos));
}

void PUTVAL16H(p2p_uint8_t *buf, unsigned pos, p2p_uint16_t hval)
{
    buf[pos+0] = (p2p_uint8_t) ((hval & 0xFF00) >> 8);
    buf[pos+1] = (p2p_uint8_t) ((hval & 0x00FF) >> 0);
}

p2p_uint32_t GETVAL32H(const p2p_uint8_t *buf, unsigned pos)
{
    return (p2p_uint32_t) ((buf[pos + 0] << 24UL) | \
						  (buf[pos + 1] << 16UL) | \
						  (buf[pos + 2] <<  8UL) | \
						  (buf[pos + 3] <<  0UL));
}

p2p_uint32_t GETVAL32N(const p2p_uint8_t *buf, unsigned pos)
{
    return htonl(GETVAL32H(buf,pos));
}

void PUTVAL32H(p2p_uint8_t *buf, unsigned pos, p2p_uint32_t hval)
{
    buf[pos+0] = (p2p_uint8_t) ((hval & 0xFF000000UL) >> 24);
    buf[pos+1] = (p2p_uint8_t) ((hval & 0x00FF0000UL) >> 16);
    buf[pos+2] = (p2p_uint8_t) ((hval & 0x0000FF00UL) >>  8);
    buf[pos+3] = (p2p_uint8_t) ((hval & 0x000000FFUL) >>  0);
}

#define INIT_ATTR(a,t,l)    (a)->hdr.type=(p2p_uint16_t)(t), \
			    (a)->hdr.length=(p2p_uint16_t)(l)
#define ATTR_HDR_LEN	    4


static void GETATTRHDR(const p2p_uint8_t *buf, rdv_attr_hdr *hdr)
{
    hdr->type = GETVAL16H(buf, 0);
    hdr->length = GETVAL16H(buf, 2);
}


struct attr_desc 
{
	int (*decode_attr) (const p2p_uint8_t *buf, void **p_attr);
	int (*encode_attr) (const void *a, 
							   p2p_uint8_t * buf, 
							   unsigned len, 
							   unsigned *printed);
};

static int decode_uint_attr(const p2p_uint8_t *buf, void **p_attr);

static int encode_uint_attr (const void *a, p2p_uint8_t * buf,
							 unsigned len, unsigned *printed);

static int decode_string_attr(const p2p_uint8_t *buf, void **p_attr);

static int encode_string_attr (const void *a, p2p_uint8_t * buf,
							   unsigned len, unsigned *printed);

static int decode_binary_attr(const p2p_uint8_t *buf, void **p_attr);

static int encode_binary_attr (const void *a, p2p_uint8_t * buf,
							   unsigned len, unsigned *printed);

static struct attr_desc rdv_attr_desc [] = 
{
  {
		/* type zero */
		0,
		0
  },
  {

		&decode_uint_attr,
		&encode_uint_attr
  },
  {
		&decode_string_attr,
		&encode_string_attr
  },
  {
		&decode_binary_attr,
		&encode_binary_attr
  },
  /* Sentinel */
	{
		0,
		0
  }
};

static const struct attr_desc *find_attr_desc(unsigned attr_type)
{
  struct attr_desc *desc;

  if (attr_type < RDV_ATTR_END_ATTR)
		desc = &rdv_attr_desc[attr_type];
	else
		return 0;

  return desc->decode_attr == 0 ? 0 : desc;
}


int rdv_msg_create (unsigned msg_type, rdv_msg **p_msg)
{
  rdv_msg *msg;

  msg = (rdv_msg *) calloc(1, sizeof (rdv_msg));
  msg->hdr.type = msg_type;
	msg->hdr.length = 0;
	msg->attr_count = 0;
	*p_msg = msg;
	return 0;
}

int rdv_msg_add_attr (rdv_msg *msg, rdv_attr_hdr *attr)
{
	if (RDV_MAX_ATTR > msg->attr_count)
		msg->attr[msg->attr_count++] = attr;
	return 0;
}


int rdv_uint_attr_create (int attr_type, p2p_uint32_t value, 
													rdv_uint_attr **p_attr)
{
	rdv_uint_attr *attr;

  attr = (rdv_uint_attr *) calloc(1, sizeof (rdv_uint_attr));
  
	INIT_ATTR(attr, attr_type, 4);
  attr->value = value;

  *p_attr = attr;

  return 0;
}

int rdv_msg_add_uint_attr (rdv_msg *msg, int attr_type, p2p_uint32_t value)
{
  rdv_uint_attr *attr = 0;
  int status;

  status = rdv_uint_attr_create(attr_type, value, &attr);
  if (status != 0)
		return status;

  return rdv_msg_add_attr (msg, &attr->hdr);
}
												 
int rdv_string_attr_init (rdv_string_attr *attr, int attr_type, const char *value)
{
	INIT_ATTR(attr, attr_type, strlen (value));
	if (value && strlen (value)) {
		attr->value = (char *) calloc (1, strlen (value));
		memcpy (attr->value, value, strlen (value));
	}

	return 0;
}

int rdv_string_attr_create (int attr_type, const char *value, rdv_string_attr **p_attr)
{
	rdv_string_attr *attr;

  attr = (rdv_string_attr *) calloc (1, sizeof (rdv_string_attr));
  *p_attr = attr;

  return rdv_string_attr_init (attr, attr_type, value);
}

int rdv_msg_add_string_attr (rdv_msg *msg, int attr_type, const char *value)
{
	rdv_string_attr *attr = 0;
  int status;
    
	status = rdv_string_attr_create(attr_type, value, &attr);
  if (status != 0)
		return status;

  return rdv_msg_add_attr(msg, &attr->hdr);
}

int rdv_binary_attr_init (rdv_binary_attr *attr,int attr_type,const p2p_uint8_t *data,unsigned length)
{
 // PJ_ASSERT_RETURN(attr_type, PJ_EINVAL);

  INIT_ATTR(attr, attr_type, length);

  if (data && length) {
		attr->length = length;
		attr->data = (p2p_uint8_t*) malloc (length);
		memcpy(attr->data, data, length);

  } else {
	//	pj_assert (0);
		attr->data = NULL;
		attr->length = 0;
  }

  return 0;
}

int rdv_binary_attr_create(int attr_type,const p2p_uint8_t *data,unsigned length,rdv_binary_attr **p_attr)
{
  rdv_binary_attr *attr;

  //PJ_ASSERT_RETURN(attr_type && p_attr, PJ_EINVAL);

  attr = (rdv_binary_attr *) calloc (1, sizeof (rdv_binary_attr));
  *p_attr = attr;
  return rdv_binary_attr_init(attr, attr_type, data, length);
}

int rdv_msg_add_binary_attr(rdv_msg *msg,int attr_type,const p2p_uint8_t *data,unsigned length)
{
  rdv_binary_attr *attr = NULL;
  int status;

  status = rdv_binary_attr_create(attr_type, data, length, &attr);
  if (status != P2P_SUCCESS)
		return status;

  return rdv_msg_add_attr(msg, &attr->hdr);
}


rdv_attr_hdr *rdv_msg_find_attr (const rdv_msg *msg, int attr_type, unsigned index)
{

  for (; index < msg->attr_count; ++index) {
		if (msg->attr[index]->type == attr_type)
	    return (rdv_attr_hdr*) msg->attr[index];
  }
   return 0;
}

int rdv_msg_encode (rdv_msg *msg, p2p_uint8_t *pkt_buf, 
										size_t buf_size, size_t *p_msg_len)
{
	p2p_uint8_t *start = pkt_buf;
	unsigned printed = 0, body_len;

	int status;

	if (buf_size < sizeof(rdv_msg_hdr))
		return -1;

	PUTVAL16H(pkt_buf, 0, msg->hdr.type);
  PUTVAL16H(pkt_buf, 2, 0);   /* length will be calculated later */
	
  pkt_buf += sizeof(rdv_msg_hdr);
  buf_size -= sizeof(rdv_msg_hdr);

  /* Encode each attribute to the message */
  for (unsigned i=0; i<msg->attr_count; ++i) 
	{
		const struct attr_desc *adesc;
		const rdv_attr_hdr *attr_hdr = msg->attr[i];
	
		adesc = find_attr_desc(attr_hdr->type);
		if (adesc) {			
			status = adesc->encode_attr(attr_hdr, pkt_buf, (unsigned)buf_size, &printed);
		} else {
			if (status != 0)
				return status;
		}

		pkt_buf += printed;
		buf_size -= printed;
		
	}

	body_len = (p2p_uint16_t) ((pkt_buf - start) - 4);

	/* hdr->length = pj_htons(length); */    
	PUTVAL16H(start, 2, (p2p_uint16_t)body_len);

  /* Update message length. */
  msg->hdr.length = (p2p_uint16_t) ((pkt_buf - start) - 4);

  /* Return the length */
  if (p_msg_len)
		*p_msg_len = (pkt_buf - start);

	return 0;
}

int rdv_msg_decode (const p2p_uint8_t *pdu, 
					size_t pdu_len,		
					rdv_msg *msg, 
					size_t *p_parsed_len, 
					rdv_msg **p_response)
{

	unsigned uattr_cnt;
	const p2p_uint8_t *start_pdu = pdu;
	int status;

	if (p_parsed_len)
		*p_parsed_len = 0;
  
	if (p_response)
		*p_response = NULL;

	memcpy (&msg->hdr, pdu, sizeof (rdv_msg_hdr));
	
	msg->hdr.type =	ntohs(msg->hdr.type);
	msg->hdr.length = ntohs(msg->hdr.length);
	msg->attr_count = 0;

	pdu += sizeof(rdv_msg_hdr);
	pdu_len = msg->hdr.length;
    
	uattr_cnt = 0;  
	while (pdu_len >= 4) 
	{	
		unsigned attr_type, attr_val_len;	
		const struct attr_desc *adesc;

		attr_type = GETVAL16H(pdu, 0);
		attr_val_len = GETVAL16H(pdu, 2);
		attr_val_len = (attr_val_len + 3) & (~3);

		if (pdu_len < attr_val_len) {
			return -11;
		}

		adesc = find_attr_desc(attr_type);

		if (adesc == NULL) {
		}
		else 
		{
			void *attr;

			/* Parse the attribute */
			status = (adesc->decode_attr)(pdu, &attr);
			if (msg->attr_count >= RDV_MAX_ATTR) {
				return -100;	
			}

			/* Add the attribute */
			msg->attr[msg->attr_count++] = (rdv_attr_hdr*)attr;
		}
		
		/* Next attribute */
		if (attr_val_len + 4 >= pdu_len) {
			pdu += pdu_len;
			pdu_len = 0;
		} else {
			pdu += (attr_val_len + 4);
			pdu_len -= (attr_val_len + 4);
		}
	}

	if (p_parsed_len)
		*p_parsed_len = (pdu - start_pdu);

	return 0;
}


void rdv_msg_destroy (rdv_msg *msg)
{
	for (unsigned i = 0; i < msg->attr_count; ++i)
	{
		if (RDV_ATTR_ID == msg->attr[i]->type)
		{
			rdv_string_attr * attr = (rdv_string_attr*) msg->attr[i];
			//free(attr->value);
			free(attr);
		}
		else if (RDV_ATTR_SD == msg->attr[i]->type)
		{
			rdv_binary_attr * attr = (rdv_binary_attr*) msg->attr[i];
			free(attr->data);
			free(attr);
		}
		else if (RDV_ATTR_USN == msg->attr[i]->type)
		{
			free (msg->attr[i]);
		}
		else
			assert (!"rdv_msg destroy error");
	}

	free (msg);
}



int decode_uint_attr(const p2p_uint8_t *buf, void **p_attr)
{
	rdv_uint_attr *attr;

  /* Create the attribute */
  attr = (rdv_uint_attr*) malloc(sizeof (rdv_uint_attr));
  GETATTRHDR(buf, &attr->hdr);

  attr->value = GETVAL32H(buf, 4);

  /* Check that the attribute length is valid */
  if (attr->hdr.length != 4)
		return -11;

  /* Done */
	*p_attr = attr;

	return 0;
}

int encode_uint_attr (const void *a, p2p_uint8_t * buf,
											unsigned len, unsigned *printed)
{

  const rdv_uint_attr *ca = (const rdv_uint_attr*)a;
  
  if (len < 8) 
		return -11;

  PUTVAL16H(buf, 0, ca->hdr.type);
  PUTVAL16H(buf, 2, (p2p_uint16_t)4);
  PUTVAL32H(buf, 4, ca->value);
    
  /* Done */
  *printed = 8;

	return 0;
}



int decode_string_attr(const p2p_uint8_t *buf, void **p_attr)
{
	rdv_string_attr *attr;

  /* Create the attribute */
  attr = (rdv_string_attr*) malloc(sizeof (rdv_string_attr));
  GETATTRHDR(buf, &attr->hdr);

	attr->value = (char *) malloc(attr->hdr.length + 1);
  memcpy (attr->value, buf+ATTR_HDR_LEN, attr->hdr.length+1);
	attr->value[attr->hdr.length] = '\0';
  /* Check that the attribute length is valid */
  if (attr->hdr.length == 0 || attr->hdr.length > RDV_MAX_ATTR)
		return -11;

  /* Done */
	*p_attr = attr;
	
	return 0;
}

int encode_string_attr (const void *a, p2p_uint8_t * buf,
										unsigned len, unsigned *printed)
{  

  const rdv_string_attr *ca = (const rdv_string_attr*)a;

  /* Calculated total attr_len (add padding if necessary) */
  *printed = (ca->hdr.length + ATTR_HDR_LEN + 3) & (~3);
  
	if (len < *printed) {
		*printed = 0;
		return -1000;
  }

  PUTVAL16H(buf, 0, ca->hdr.type);
  PUTVAL16H(buf, 2, (p2p_uint16_t)ca->hdr.length);

  /* Copy the string */
  memcpy(buf+ATTR_HDR_LEN, ca->value, ca->hdr.length);

  /* Add padding character, if string is not 4-bytes aligned. */
  if (ca->hdr.length & 0x03) {
		p2p_uint8_t pad[3];
		memset(pad, 0, sizeof(pad));
		memcpy(buf+ATTR_HDR_LEN+ca->hdr.length, pad, 4-(ca->hdr.length & 0x03));
	}

	return 0;
}

int decode_binary_attr(const p2p_uint8_t *buf, void **p_attr)
{
  rdv_binary_attr *attr;

  /* Create the attribute */
  attr = (rdv_binary_attr*) malloc(sizeof (rdv_binary_attr));
  GETATTRHDR(buf, &attr->hdr);

  /* Copy the data to the attribute */
  attr->length = attr->hdr.length;
  attr->data = (p2p_uint8_t*) malloc(attr->length);
  memcpy(attr->data, buf+ATTR_HDR_LEN, attr->length);

  /* Done */
  *p_attr = attr;

	return 0;
}

int encode_binary_attr (const void *a, p2p_uint8_t * buf, 
												unsigned len, unsigned *printed)
{ 
	const rdv_binary_attr *ca = (const rdv_binary_attr*)a;

  /* Calculated total attr_len (add padding if necessary) */
  *printed = (ca->length + ATTR_HDR_LEN + 3) & (~3);
  if (len < *printed)
		return -11;

  PUTVAL16H(buf, 0, ca->hdr.type);
  PUTVAL16H(buf, 2, (p2p_uint16_t) ca->length);

  /* Copy the data */
  memcpy(buf+ATTR_HDR_LEN, ca->data, ca->length);
	return 0;
}