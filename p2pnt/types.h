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

#ifndef __P2P_TYPES_H__
#define __P2P_TYPES_H__


/** Signed 32bit integer. */
typedef int	p2p_int32_t;

/** Unsigned 32bit integer. */
typedef unsigned int p2p_uint32_t;

/** Signed 16bit integer. */
typedef short	p2p_int16_t;

/** Unsigned 16bit integer. */
typedef unsigned short p2p_uint16_t;

/** Signed 8bit integer. */
typedef signed char	p2p_int8_t;

/** Unsigned 8bit integer. */
typedef unsigned char	p2p_uint8_t;

/** Status code. */
typedef int	p2p_status_t;

/** Boolean. */
typedef int	p2p_bool_t;

/** Status is OK. */
#define P2P_SUCCESS  0

/** True value. */
#define P2P_TRUE	1

/** False value. */
#define P2P_FALSE	0


p2p_uint16_t GETVAL16H(const p2p_uint8_t *buf, unsigned pos);

p2p_uint16_t GETVAL16N(const p2p_uint8_t *buf, unsigned pos);

void PUTVAL16H(p2p_uint8_t *buf, unsigned pos, p2p_uint16_t hval);

p2p_uint32_t GETVAL32H(const p2p_uint8_t *buf, unsigned pos);

p2p_uint32_t GETVAL32N(const p2p_uint8_t *buf, unsigned pos);

void PUTVAL32H(p2p_uint8_t *buf, unsigned pos, p2p_uint32_t hval);

#endif