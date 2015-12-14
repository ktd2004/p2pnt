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

#include "types.h"
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