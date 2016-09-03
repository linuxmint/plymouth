/* ply-seat.h - APIs for encapsulating a keyboard and one or more displays
 *
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Written By: Ray Strode <rstrode@redhat.com>
 */
#ifndef PLY_SEAT_H
#define PLY_SEAT_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "ply-boot-splash.h"
#include "ply-buffer.h"
#include "ply-event-loop.h"
#include "ply-keyboard.h"
#include "ply-list.h"
#include "ply-pixel-display.h"
#include "ply-terminal.h"
#include "ply-text-display.h"

typedef struct _ply_boot_splash ply_boot_splash_t;
typedef struct _ply_seat ply_seat_t;

#ifndef PLY_HIDE_FUNCTION_DECLARATIONS
ply_seat_t *ply_seat_new (ply_terminal_t *terminal);

void ply_seat_free (ply_seat_t *seat);
bool ply_seat_open (ply_seat_t         *seat,
                    ply_renderer_type_t renderer_type,
                    const char         *device);
bool ply_seat_is_open (ply_seat_t *seat);
void ply_seat_deactivate_keyboard (ply_seat_t *seat);
void ply_seat_activate_keyboard (ply_seat_t *seat);
void ply_seat_deactivate_renderer (ply_seat_t *seat);
void ply_seat_activate_renderer (ply_seat_t *seat);
void ply_seat_refresh_displays (ply_seat_t *seat);
void ply_seat_close (ply_seat_t *seat);
void ply_seat_set_splash (ply_seat_t        *seat,
                          ply_boot_splash_t *splash);

ply_list_t *ply_seat_get_pixel_displays (ply_seat_t *seat);
ply_list_t *ply_seat_get_text_displays (ply_seat_t *seat);
ply_keyboard_t *ply_seat_get_keyboard (ply_seat_t *seat);
ply_renderer_t *ply_seat_get_renderer (ply_seat_t *seat);
#endif

#endif /* PLY_SEAT_H */
/* vim: set ts=4 sw=4 et ai ci cino={.5s,^-2,+.5s,t0,g0,e-2,n-2,p2s,(0,=.5s,:.5s */
