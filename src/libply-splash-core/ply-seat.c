/* ply-seat.c - APIs for encapsulating a keyboard and one or more displays
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
 * Written by: Ray Strode <rstrode@redhat.com>
 */
#include "config.h"
#include "ply-seat.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ply-boot-splash.h"
#include "ply-event-loop.h"
#include "ply-keyboard.h"
#include "ply-pixel-display.h"
#include "ply-text-display.h"
#include "ply-list.h"
#include "ply-logger.h"
#include "ply-utils.h"

struct _ply_seat
{
        ply_event_loop_t  *loop;

        ply_boot_splash_t *splash;
        ply_terminal_t    *terminal;
        ply_renderer_t    *renderer;
        ply_keyboard_t    *keyboard;
        ply_list_t        *text_displays;
        ply_list_t        *pixel_displays;

        uint32_t           renderer_active : 1;
        uint32_t           keyboard_active : 1;
};

ply_seat_t *
ply_seat_new (ply_terminal_t *terminal)
{
        ply_seat_t *seat;

        seat = calloc (1, sizeof(ply_seat_t));

        seat->loop = ply_event_loop_get_default ();
        seat->terminal = terminal;
        seat->text_displays = ply_list_new ();
        seat->pixel_displays = ply_list_new ();

        return seat;
}

static void
add_pixel_displays (ply_seat_t *seat)
{
        ply_list_t *heads;
        ply_list_node_t *node;

        heads = ply_renderer_get_heads (seat->renderer);

        ply_trace ("Adding displays for %d heads",
                   ply_list_get_length (heads));

        node = ply_list_get_first_node (heads);
        while (node != NULL) {
                ply_list_node_t *next_node;
                ply_renderer_head_t *head;
                ply_pixel_display_t *display;

                head = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (heads, node);

                display = ply_pixel_display_new (seat->renderer, head);

                ply_list_append_data (seat->pixel_displays, display);

                node = next_node;
        }
}

static void
add_text_displays (ply_seat_t *seat)
{
        ply_text_display_t *display;

        if (!ply_terminal_is_open (seat->terminal)) {
                if (!ply_terminal_open (seat->terminal)) {
                        ply_trace ("could not add terminal %s: %m",
                                   ply_terminal_get_name (seat->terminal));
                        return;
                }
        }

        ply_trace ("adding text display for terminal %s",
                   ply_terminal_get_name (seat->terminal));

        display = ply_text_display_new (seat->terminal);
        ply_list_append_data (seat->text_displays, display);
}

bool
ply_seat_open (ply_seat_t         *seat,
               ply_renderer_type_t renderer_type,
               const char         *device)
{
        if (renderer_type != PLY_RENDERER_TYPE_NONE) {
                ply_renderer_t *renderer;

                renderer = ply_renderer_new (renderer_type, device, seat->terminal);

                if (!ply_renderer_open (renderer)) {
                        ply_trace ("could not open renderer for %s", device);
                        ply_renderer_free (renderer);

                        seat->renderer = NULL;
                        seat->renderer_active = false;

                        if (renderer_type != PLY_RENDERER_TYPE_AUTO)
                                return false;
                } else {
                        seat->renderer = renderer;
                        seat->renderer_active = true;
                }
        }

        if (seat->renderer != NULL) {
                seat->keyboard = ply_keyboard_new_for_renderer (seat->renderer);
                add_pixel_displays (seat);
        } else if (seat->terminal != NULL) {
                seat->keyboard = ply_keyboard_new_for_terminal (seat->terminal);
        }

        if (seat->terminal != NULL) {
                add_text_displays (seat);
        } else {
                ply_trace ("not adding text display for seat, since seat has no associated terminal");
        }

        if (seat->keyboard != NULL) {
                ply_keyboard_watch_for_input (seat->keyboard);
                seat->keyboard_active = true;
        } else {
                ply_trace ("not watching seat for input");
        }

        return true;
}

bool
ply_seat_is_open (ply_seat_t *seat)
{
        return ply_list_get_length (seat->pixel_displays) > 0 ||
               ply_list_get_length (seat->text_displays) > 0;
}

void
ply_seat_deactivate_keyboard (ply_seat_t *seat)
{
        if (!seat->keyboard_active)
                return;

        seat->keyboard_active = false;

        if (seat->keyboard == NULL)
                return;

        ply_trace ("deactivating keyboard");
        ply_keyboard_stop_watching_for_input (seat->keyboard);
}

void
ply_seat_deactivate_renderer (ply_seat_t *seat)
{
        if (!seat->renderer_active)
                return;

        seat->renderer_active = false;

        if (seat->renderer == NULL)
                return;

        ply_trace ("deactivating renderer");
        ply_renderer_deactivate (seat->renderer);
}

void
ply_seat_activate_keyboard (ply_seat_t *seat)
{
        if (seat->keyboard_active)
                return;

        if (seat->keyboard == NULL)
                return;

        ply_trace ("activating keyboard");
        ply_keyboard_watch_for_input (seat->keyboard);

        seat->keyboard_active = true;
}

void
ply_seat_activate_renderer (ply_seat_t *seat)
{
        if (seat->renderer_active)
                return;

        if (seat->renderer == NULL)
                return;

        ply_trace ("activating renderer");
        ply_renderer_activate (seat->renderer);

        seat->renderer_active = true;
}

void
ply_seat_refresh_displays (ply_seat_t *seat)
{
        ply_list_node_t *node;

        node = ply_list_get_first_node (seat->pixel_displays);
        while (node != NULL) {
                ply_pixel_display_t *display;
                ply_list_node_t *next_node;
                unsigned long width, height;

                display = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (seat->pixel_displays, node);

                width = ply_pixel_display_get_width (display);
                height = ply_pixel_display_get_height (display);

                ply_pixel_display_draw_area (display, 0, 0, width, height);
                node = next_node;
        }

        node = ply_list_get_first_node (seat->text_displays);
        while (node != NULL) {
                ply_text_display_t *display;
                ply_list_node_t *next_node;
                int number_of_columns, number_of_rows;

                display = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (seat->text_displays, node);

                number_of_columns = ply_text_display_get_number_of_columns (display);
                number_of_rows = ply_text_display_get_number_of_rows (display);

                ply_text_display_draw_area (display, 0, 0,
                                            number_of_columns,
                                            number_of_rows);
                node = next_node;
        }
}

void
ply_seat_close (ply_seat_t *seat)
{
        if (seat->renderer == NULL)
                return;

        ply_trace ("destroying renderer");
        ply_renderer_close (seat->renderer);
        ply_renderer_free (seat->renderer);
        seat->renderer = NULL;
}

void
ply_seat_set_splash (ply_seat_t        *seat,
                     ply_boot_splash_t *splash)
{
        if (seat->splash == splash)
                return;

        if (seat->splash != NULL)
                ply_boot_splash_detach_from_seat (splash, seat);

        if (splash != NULL)
                ply_boot_splash_attach_to_seat (splash, seat);

        seat->splash = splash;
}

static void
free_pixel_displays (ply_seat_t *seat)
{
        ply_list_node_t *node;

        ply_trace ("freeing %d pixel displays", ply_list_get_length (seat->pixel_displays));
        node = ply_list_get_first_node (seat->pixel_displays);
        while (node != NULL) {
                ply_list_node_t *next_node;
                ply_pixel_display_t *display;

                next_node = ply_list_get_next_node (seat->pixel_displays, node);
                display = ply_list_node_get_data (node);
                ply_pixel_display_free (display);

                ply_list_remove_node (seat->pixel_displays, node);

                node = next_node;
        }
}

static void
free_text_displays (ply_seat_t *seat)
{
        ply_list_node_t *node;

        ply_trace ("freeing %d text displays", ply_list_get_length (seat->text_displays));
        node = ply_list_get_first_node (seat->text_displays);
        while (node != NULL) {
                ply_list_node_t *next_node;
                ply_text_display_t *display;

                next_node = ply_list_get_next_node (seat->text_displays, node);
                display = ply_list_node_get_data (node);
                ply_text_display_free (display);

                ply_list_remove_node (seat->text_displays, node);

                node = next_node;
        }
}

void
ply_seat_free (ply_seat_t *seat)
{
        if (seat == NULL)
                return;

        free_pixel_displays (seat);
        free_text_displays (seat);
        ply_keyboard_free (seat->keyboard);

        free (seat);
}

ply_list_t *
ply_seat_get_pixel_displays (ply_seat_t *seat)
{
        return seat->pixel_displays;
}

ply_list_t *
ply_seat_get_text_displays (ply_seat_t *seat)
{
        return seat->text_displays;
}

ply_keyboard_t *
ply_seat_get_keyboard (ply_seat_t *seat)
{
        return seat->keyboard;
}

ply_renderer_t *
ply_seat_get_renderer (ply_seat_t *seat)
{
        return seat->renderer;
}

/* vim: set ts=4 sw=4 et ai ci cino={.5s,^-2,+.5s,t0,g0,e-2,n-2,p2s,(0,=.5s,:.5s */
