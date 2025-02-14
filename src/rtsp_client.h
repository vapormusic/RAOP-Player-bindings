/*****************************************************************************
 * rtsp_client.h: RTSP Client
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Copyright (C) 2016 Philippe <philippe44@outlook.com>
 * Copyright (C) 2021 David Klopp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/

#ifndef __RTSP_CLIENT_H
#define __RTSP_CLIENT_H

#include "dmap.h"

struct rtspcl_s;
struct rtp_port_s;
struct digest_info_s;

struct rtspcl_s *rtspcl_create(char* user_name);
bool   			rtspcl_destroy(struct rtspcl_s *p);

bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, unsigned short destport, char *sid);
bool rtspcl_disconnect(struct rtspcl_s *p);
bool rtspcl_is_connected(struct rtspcl_s *p);
bool rtspcl_is_sane(struct rtspcl_s *p);
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);
bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret);
bool rtspcl_pair_pin_start(struct rtspcl_s *p);
bool rtspcl_pair_setup_pin(struct rtspcl_s *p, const char *pin, char **secret);
bool rtspcl_auth_setup(struct rtspcl_s *p);
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *password);
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *kd);
bool rtspcl_record(struct rtspcl_s *p, u16_t start_seq, u32_t start_ts, key_data_t *kd);
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param);
bool rtspcl_flush(struct rtspcl_s *p, u16_t seq_number, u32_t timestamp);
bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, struct dmap_entry_s *entry);
bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image);

bool rtspcl_remove_all_exthds(struct rtspcl_s *p);
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data);
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key);
char* rtspcl_local_ip(struct rtspcl_s *p);

#endif
