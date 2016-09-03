/* ply-device-manager.h - udev monitor
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
 */
#ifndef PLY_DEVICE_MANAGER_H
#define PLY_DEVICE_MANAGER_H

#include <stdbool.h>
#include "ply-seat.h"

typedef enum
{
        PLY_DEVICE_MANAGER_FLAGS_NONE = 0,
        PLY_DEVICE_MANAGER_FLAGS_IGNORE_SERIAL_CONSOLES = 1 << 0,
                PLY_DEVICE_MANAGER_FLAGS_IGNORE_UDEV = 1 << 1
} ply_device_manager_flags_t;

typedef struct _ply_device_manager ply_device_manager_t;
typedef void (*ply_seat_added_handler_t) (void       *,
                                          ply_seat_t *);
typedef void (*ply_seat_removed_handler_t) (void       *,
                                            ply_seat_t *);

#ifndef PLY_HIDE_FUNCTION_DECLARATIONS
ply_device_manager_t *ply_device_manager_new (const char                *default_tty,
                                              ply_device_manager_flags_t flags);
void ply_device_manager_watch_seats (ply_device_manager_t      *manager,
                                     ply_seat_added_handler_t   seat_added_handler,
                                     ply_seat_removed_handler_t seat_removed_handler,
                                     void                      *data);
bool ply_device_manager_has_open_seats (ply_device_manager_t *manager);
ply_list_t *ply_device_manager_get_seats (ply_device_manager_t *manager);
void ply_device_manager_free (ply_device_manager_t *manager);
void ply_device_manager_activate_keyboards (ply_device_manager_t *manager);
void ply_device_manager_deactivate_keyboards (ply_device_manager_t *manager);
void ply_device_manager_activate_renderers (ply_device_manager_t *manager);
void ply_device_manager_deactivate_renderers (ply_device_manager_t *manager);
ply_terminal_t *ply_device_manager_get_default_terminal (ply_device_manager_t *manager);

#endif

#endif
/* vim: set ts=4 sw=4 expandtab autoindent cindent cino={.5s,(0: */
