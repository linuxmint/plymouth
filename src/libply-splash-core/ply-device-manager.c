/* ply-device-manager.c - device manager
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
#include "config.h"
#include "ply-device-manager.h"

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libudev.h>

#include "ply-logger.h"
#include "ply-event-loop.h"
#include "ply-hashtable.h"
#include "ply-list.h"
#include "ply-utils.h"

#define SUBSYSTEM_DRM "drm"
#define SUBSYSTEM_FRAME_BUFFER "graphics"

static void create_seat_for_terminal_and_renderer_type (ply_device_manager_t *manager,
                                                        const char           *device_path,
                                                        ply_terminal_t       *terminal,
                                                        ply_renderer_type_t   renderer_type);
struct _ply_device_manager
{
        ply_device_manager_flags_t flags;
        ply_event_loop_t          *loop;
        ply_hashtable_t           *terminals;
        ply_terminal_t            *local_console_terminal;
        ply_seat_t                *local_console_seat;
        ply_list_t                *seats;
        struct udev               *udev_context;
        struct udev_queue         *udev_queue;
        int                        udev_queue_fd;
        ply_fd_watch_t            *udev_queue_fd_watch;
        struct udev_monitor       *udev_monitor;

        ply_seat_added_handler_t   seat_added_handler;
        ply_seat_removed_handler_t seat_removed_handler;
        void                      *seat_event_handler_data;
};

static void
detach_from_event_loop (ply_device_manager_t *manager)
{
        assert (manager != NULL);

        manager->loop = NULL;
}

static void
attach_to_event_loop (ply_device_manager_t *manager,
                      ply_event_loop_t     *loop)
{
        assert (manager != NULL);
        assert (loop != NULL);
        assert (manager->loop == NULL);

        manager->loop = loop;

        ply_event_loop_watch_for_exit (loop, (ply_event_loop_exit_handler_t)
                                       detach_from_event_loop,
                                       manager);
}

static bool
device_is_for_local_console (ply_device_manager_t *manager,
                             struct udev_device   *device)
{
        const char *device_path;
        struct udev_device *bus_device;
        char *bus_device_path;
        const char *boot_vga;
        bool for_local_console;

        /* Look at the associated bus device to see if this card is the
         * card the kernel is using for its console. */
        device_path = udev_device_get_syspath (device);
        asprintf (&bus_device_path, "%s/device", device_path);
        bus_device = udev_device_new_from_syspath (manager->udev_context, bus_device_path);

        boot_vga = udev_device_get_sysattr_value (bus_device, "boot_vga");
        free (bus_device_path);

        if (boot_vga != NULL && strcmp (boot_vga, "1") == 0)
                for_local_console = true;
        else
                for_local_console = false;

        return for_local_console;
}

static bool
drm_device_in_use (ply_device_manager_t *manager,
                   const char           *device_path)
{
        ply_list_node_t *node;

        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_renderer_t *renderer;
                ply_list_node_t *next_node;
                const char *renderer_device_path;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);
                renderer = ply_seat_get_renderer (seat);

                if (renderer != NULL) {
                        renderer_device_path = ply_renderer_get_device_name (renderer);

                        if (renderer_device_path != NULL) {
                                if (strcmp (device_path, renderer_device_path) == 0) {
                                        return true;
                                }
                        }
                }

                node = next_node;
        }

        return false;
}

static bool
fb_device_has_drm_device (ply_device_manager_t *manager,
                          struct udev_device   *fb_device)
{
        struct udev_enumerate *card_matches;
        struct udev_list_entry *card_entry;
        const char *id_path;
        bool has_drm_device = false;

        /* We want to see if the framebuffer is associated with a DRM-capable
         * graphics card, if it is, we'll use the DRM device */
        card_matches = udev_enumerate_new (manager->udev_context);
        udev_enumerate_add_match_is_initialized (card_matches);
        udev_enumerate_add_match_parent (card_matches, udev_device_get_parent (fb_device));
        udev_enumerate_add_match_subsystem (card_matches, "drm");
        id_path = udev_device_get_property_value (fb_device, "ID_PATH");
        udev_enumerate_add_match_property (card_matches, "ID_PATH", id_path);

        ply_trace ("trying to find associated drm node for fb device (path: %s)", id_path);

        udev_enumerate_scan_devices (card_matches);

        /* there should only ever be at most one match so we don't iterate through
         * the list, but just look at the first entry */
        card_entry = udev_enumerate_get_list_entry (card_matches);

        if (card_entry != NULL) {
                struct udev_device *card_device = NULL;
                const char *card_node;
                const char *card_path;

                card_path = udev_list_entry_get_name (card_entry);
                card_device = udev_device_new_from_syspath (manager->udev_context, card_path);
                card_node = udev_device_get_devnode (card_device);
                if (card_node != NULL && drm_device_in_use (manager, card_node))
                        has_drm_device = true;
                else
                        ply_trace ("no card node!");

                udev_device_unref (card_device);
        } else {
                ply_trace ("no card entry!");
        }

        udev_enumerate_unref (card_matches);
        return has_drm_device;
}

static void
create_seat_for_udev_device (ply_device_manager_t *manager,
                             struct udev_device   *device)
{
        bool for_local_console;
        const char *device_path;
        ply_terminal_t *terminal = NULL;

        for_local_console = device_is_for_local_console (manager, device);

        ply_trace ("device is for local console: %s", for_local_console ? "yes" : "no");

        if (for_local_console)
                terminal = manager->local_console_terminal;

        device_path = udev_device_get_devnode (device);

        if (device_path != NULL) {
                const char *subsystem;
                ply_renderer_type_t renderer_type = PLY_RENDERER_TYPE_NONE;

                subsystem = udev_device_get_subsystem (device);
                ply_trace ("device subsystem is %s", subsystem);

                if (subsystem != NULL && strcmp (subsystem, SUBSYSTEM_DRM) == 0) {
                        ply_trace ("found DRM device %s", device_path);
                        renderer_type = PLY_RENDERER_TYPE_DRM;
                } else if (strcmp (subsystem, SUBSYSTEM_FRAME_BUFFER) == 0) {
                        ply_trace ("found frame buffer device %s", device_path);
                        if (!fb_device_has_drm_device (manager, device))
                                renderer_type = PLY_RENDERER_TYPE_FRAME_BUFFER;
                        else
                                ply_trace ("ignoring, since there's a DRM device associated with it");
                }

                if (renderer_type != PLY_RENDERER_TYPE_NONE) {
                        create_seat_for_terminal_and_renderer_type (manager,
                                                                    device_path,
                                                                    terminal,
                                                                    renderer_type);
                }
        }
}

static void
free_seat_from_device_path (ply_device_manager_t *manager,
                            const char           *device_path)
{
        ply_list_node_t *node;

        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_renderer_t *renderer;
                ply_list_node_t *next_node;
                const char *renderer_device_path;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);
                renderer = ply_seat_get_renderer (seat);

                if (renderer != NULL) {
                        renderer_device_path = ply_renderer_get_device_name (renderer);

                        if (renderer_device_path != NULL) {
                                if (strcmp (device_path, renderer_device_path) == 0) {
                                        ply_trace ("removing seat associated with %s", device_path);

                                        if (manager->seat_removed_handler != NULL)
                                                manager->seat_removed_handler (manager->seat_event_handler_data, seat);

                                        ply_seat_free (seat);
                                        ply_list_remove_node (manager->seats, node);
                                        break;
                                }
                        }
                }

                node = next_node;
        }
}

static void
free_seat_for_udev_device (ply_device_manager_t *manager,
                           struct udev_device   *device)
{
        const char *device_path;

        device_path = udev_device_get_devnode (device);

        if (device_path != NULL)
                free_seat_from_device_path (manager, device_path);
}

static bool
create_seats_for_subsystem (ply_device_manager_t *manager,
                            const char           *subsystem)
{
        struct udev_enumerate *matches;
        struct udev_list_entry *entry;
        bool found_device = false;

        ply_trace ("creating seats for %s devices",
                   strcmp (subsystem, SUBSYSTEM_FRAME_BUFFER) == 0 ?
                   "frame buffer" :
                   subsystem);

        matches = udev_enumerate_new (manager->udev_context);
        udev_enumerate_add_match_subsystem (matches, subsystem);
        udev_enumerate_scan_devices (matches);

        udev_list_entry_foreach (entry, udev_enumerate_get_list_entry (matches)){
                struct udev_device *device = NULL;
                const char *path;

                path = udev_list_entry_get_name (entry);

                if (path == NULL) {
                        ply_trace ("path was null!");
                        continue;
                }

                ply_trace ("found device %s", path);

                device = udev_device_new_from_syspath (manager->udev_context, path);

                /* if device isn't fully initialized, we'll get an add event later
                 */
                if (udev_device_get_is_initialized (device)) {
                        ply_trace ("device is initialized");

                        /* We only care about devices assigned to a (any) seat. Floating
                         * devices should be ignored.
                         */
                        if (true) {
                                const char *node;
                                node = udev_device_get_devnode (device);
                                if (node != NULL) {
                                        ply_trace ("found node %s", node);
                                        found_device = true;
                                        create_seat_for_udev_device (manager, device);
                                }
                        } else {
                                ply_trace ("device doesn't have a seat tag");
                        }
                } else {
                        ply_trace ("it's not initialized");
                }

                udev_device_unref (device);
        }

        udev_enumerate_unref (matches);

        return found_device;
}

static void
on_udev_event (ply_device_manager_t *manager)
{
        struct udev_device *device;
        const char *action;

        device = udev_monitor_receive_device (manager->udev_monitor);
        if (device == NULL)
                return;

        action = udev_device_get_action (device);

        ply_trace ("got %s event for device %s", action, udev_device_get_sysname (device));

        if (action == NULL)
                return;

        if (strcmp (action, "add") == 0) {
                const char *subsystem;
                bool coldplug_complete = manager->udev_queue_fd_watch == NULL;

                subsystem = udev_device_get_subsystem (device);

                if (strcmp (subsystem, SUBSYSTEM_DRM) == 0 ||
                    coldplug_complete)
                        create_seat_for_udev_device (manager, device);
                else
                        ply_trace ("ignoring since we only handle subsystem %s devices after coldplug completes", subsystem);
        } else if (strcmp (action, "remove") == 0) {
                free_seat_for_udev_device (manager, device);
        }

        udev_device_unref (device);
}

static void
watch_for_udev_events (ply_device_manager_t *manager)
{
        int fd;

        assert (manager != NULL);
        assert (manager->udev_monitor == NULL);

        ply_trace ("watching for udev graphics device add and remove events");

        manager->udev_monitor = udev_monitor_new_from_netlink (manager->udev_context, "udev");

        udev_monitor_filter_add_match_subsystem_devtype (manager->udev_monitor, SUBSYSTEM_DRM, NULL);
        udev_monitor_filter_add_match_subsystem_devtype (manager->udev_monitor, SUBSYSTEM_FRAME_BUFFER, NULL);
        udev_monitor_filter_add_match_tag (manager->udev_monitor, "seat");
        udev_monitor_enable_receiving (manager->udev_monitor);

        fd = udev_monitor_get_fd (manager->udev_monitor);
        ply_event_loop_watch_fd (manager->loop,
                                 fd,
                                 PLY_EVENT_LOOP_FD_STATUS_HAS_DATA,
                                 (ply_event_handler_t)
                                 on_udev_event,
                                 NULL,
                                 manager);
}

static void
free_seats (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        ply_trace ("removing seats");
        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                if (manager->seat_removed_handler != NULL)
                        manager->seat_removed_handler (manager->seat_event_handler_data, seat);

                ply_seat_free (seat);
                ply_list_remove_node (manager->seats, node);

                node = next_node;
        }
}

static void
free_terminal (char                 *device,
               ply_terminal_t       *terminal,
               ply_device_manager_t *manager)
{
        ply_hashtable_remove (manager->terminals, device);

        ply_terminal_free (terminal);
}

static void
free_terminals (ply_device_manager_t *manager)
{
        ply_hashtable_foreach (manager->terminals,
                               (ply_hashtable_foreach_func_t *)
                               free_terminal,
                               manager);
}

static ply_terminal_t *
get_terminal (ply_device_manager_t *manager,
              const char           *device_name)
{
        char *full_name = NULL;
        ply_terminal_t *terminal;

        if (strncmp (device_name, "/dev/", strlen ("/dev/")) == 0)
                full_name = strdup (device_name);
        else
                asprintf (&full_name, "/dev/%s", device_name);

        if (strcmp (full_name, "/dev/tty0") == 0 ||
            strcmp (full_name, "/dev/tty") == 0 ||
            strcmp (full_name, ply_terminal_get_name (manager->local_console_terminal)) == 0) {
                terminal = manager->local_console_terminal;
                goto done;
        }

        terminal = ply_hashtable_lookup (manager->terminals, full_name);

        if (terminal == NULL) {
                terminal = ply_terminal_new (full_name);

                ply_hashtable_insert (manager->terminals,
                                      (void *) ply_terminal_get_name (terminal),
                                      terminal);
        }

done:
        free (full_name);
        return terminal;
}

ply_device_manager_t *
ply_device_manager_new (const char                *default_tty,
                        ply_device_manager_flags_t flags)
{
        ply_device_manager_t *manager;

        manager = calloc (1, sizeof(ply_device_manager_t));
        manager->loop = NULL;
        manager->terminals = ply_hashtable_new (ply_hashtable_string_hash, ply_hashtable_string_compare);
        manager->local_console_terminal = ply_terminal_new (default_tty);
        ply_hashtable_insert (manager->terminals,
                              (void *) ply_terminal_get_name (manager->local_console_terminal),
                              manager->local_console_terminal);
        manager->seats = ply_list_new ();
        manager->flags = flags;

        if (!(flags & PLY_DEVICE_MANAGER_FLAGS_IGNORE_UDEV))
                manager->udev_context = udev_new ();

        attach_to_event_loop (manager, ply_event_loop_get_default ());

        return manager;
}

void
ply_device_manager_free (ply_device_manager_t *manager)
{
        ply_trace ("freeing device manager");

        if (manager == NULL)
                return;

        ply_event_loop_stop_watching_for_exit (manager->loop,
                                               (ply_event_loop_exit_handler_t)
                                               detach_from_event_loop,
                                               manager);
        free_seats (manager);
        ply_list_free (manager->seats);

        free_terminals (manager);
        ply_hashtable_free (manager->terminals);

        if (manager->udev_monitor != NULL)
                udev_monitor_unref (manager->udev_monitor);

        if (manager->udev_context != NULL)
                udev_unref (manager->udev_context);

        free (manager);
}

static bool
add_consoles_from_file (ply_device_manager_t *manager,
                        const char           *path)
{
        int fd;
        char contents[512] = "";
        ssize_t contents_length;
        bool has_serial_consoles;
        const char *remaining_file_contents;

        ply_trace ("opening %s", path);
        fd = open (path, O_RDONLY);

        if (fd < 0) {
                ply_trace ("couldn't open it: %m");
                return false;
        }

        ply_trace ("reading file");
        contents_length = read (fd, contents, sizeof(contents) - 1);

        if (contents_length <= 0) {
                ply_trace ("couldn't read it: %m");
                close (fd);
                return false;
        }
        close (fd);

        remaining_file_contents = contents;
        has_serial_consoles = false;

        while (remaining_file_contents < contents + contents_length) {
                char *console;
                size_t console_length;
                const char *console_device;
                ply_terminal_t *terminal;

                /* Advance past any leading whitespace */
                remaining_file_contents += strspn (remaining_file_contents, " \n\t\v");

                if (*remaining_file_contents == '\0')
                        /* There's nothing left after the whitespace, we're done */
                        break;

                /* Find trailing whitespace and NUL terminate.  If strcspn
                 * doesn't find whitespace, it gives us the length of the string
                 * until the next NUL byte, which we'll just overwrite with
                 * another NUL byte anyway. */
                console_length = strcspn (remaining_file_contents, " \n\t\v");
                console = strndup (remaining_file_contents, console_length);

                terminal = get_terminal (manager, console);
                console_device = ply_terminal_get_name (terminal);

                free (console);

                ply_trace ("console %s found!", console_device);

                if (terminal != manager->local_console_terminal)
                        has_serial_consoles = true;

                /* Move past the parsed console string, and the whitespace we
                 * may have found above.  If we found a NUL above and not whitespace,
                 * then we're going to jump past the end of the buffer and the loop
                 * will terminate
                 */
                remaining_file_contents += console_length + 1;
        }

        return has_serial_consoles;
}

static void
create_seat_for_terminal_and_renderer_type (ply_device_manager_t *manager,
                                            const char           *device_path,
                                            ply_terminal_t       *terminal,
                                            ply_renderer_type_t   renderer_type)
{
        ply_seat_t *seat;
        bool is_local_terminal = false;

        if (terminal != NULL && manager->local_console_terminal == terminal)
                is_local_terminal = true;

        if (is_local_terminal && manager->local_console_seat != NULL) {
                ply_trace ("trying to create seat for local console when one already exists");
                return;
        }

        ply_trace ("creating seat for %s (renderer type: %u) (terminal: %s)",
                   device_path ? : "", renderer_type, terminal ? ply_terminal_get_name (terminal) : "none");
        seat = ply_seat_new (terminal);

        if (!ply_seat_open (seat, renderer_type, device_path)) {
                ply_trace ("could not create seat");
                ply_seat_free (seat);
                return;
        }

        ply_list_append_data (manager->seats, seat);

        if (is_local_terminal)
                manager->local_console_seat = seat;

        if (manager->seat_added_handler != NULL)
                manager->seat_added_handler (manager->seat_event_handler_data, seat);
}

static void
create_seat_for_terminal (const char           *device_path,
                          ply_terminal_t       *terminal,
                          ply_device_manager_t *manager)
{
        create_seat_for_terminal_and_renderer_type (manager,
                                                    device_path,
                                                    terminal,
                                                    PLY_RENDERER_TYPE_NONE);
}
static bool
create_seats_from_terminals (ply_device_manager_t *manager)
{
        bool has_serial_consoles;

        ply_trace ("checking for consoles");

        if (manager->flags & PLY_DEVICE_MANAGER_FLAGS_IGNORE_SERIAL_CONSOLES) {
                has_serial_consoles = false;
                ply_trace ("ignoring all consoles but default console because explicitly told to.");
        } else {
                has_serial_consoles = add_consoles_from_file (manager, "/sys/class/tty/console/active");
        }

        if (has_serial_consoles) {
                ply_trace ("serial consoles detected, managing them with details forced");
                ply_hashtable_foreach (manager->terminals,
                                       (ply_hashtable_foreach_func_t *)
                                       create_seat_for_terminal,
                                       manager);
                return true;
        }

        return false;
}

static void
create_seats_from_udev (ply_device_manager_t *manager)
{
        bool found_drm_device, found_fb_device;

        ply_trace ("Looking for devices from udev");

        found_drm_device = create_seats_for_subsystem (manager, SUBSYSTEM_DRM);
        found_fb_device = create_seats_for_subsystem (manager, SUBSYSTEM_FRAME_BUFFER);

        if (found_drm_device || found_fb_device)
                return;

        ply_trace ("Creating non-graphical seat, since there's no suitable graphics hardware");
        create_seat_for_terminal_and_renderer_type (manager,
                                                    ply_terminal_get_name (manager->local_console_terminal),
                                                    manager->local_console_terminal,
                                                    PLY_RENDERER_TYPE_NONE);
}

static void
create_fallback_seat (ply_device_manager_t *manager)
{
        create_seat_for_terminal_and_renderer_type (manager,
                                                    ply_terminal_get_name (manager->local_console_terminal),
                                                    manager->local_console_terminal,
                                                    PLY_RENDERER_TYPE_AUTO);
}

static void
on_udev_queue_changed (ply_device_manager_t *manager)
{
        if (!udev_queue_get_queue_is_empty (manager->udev_queue))
                return;

        ply_trace ("udev coldplug complete");
        ply_event_loop_stop_watching_fd (manager->loop, manager->udev_queue_fd_watch);
        manager->udev_queue_fd_watch = NULL;
        udev_queue_unref (manager->udev_queue);

        close (manager->udev_queue_fd);
        manager->udev_queue_fd = -1;

        manager->udev_queue = NULL;

        create_seats_from_udev (manager);
}

static void
watch_for_coldplug_completion (ply_device_manager_t *manager)
{
        int fd;
        int result;

        manager->udev_queue = udev_queue_new (manager->udev_context);

        if (udev_queue_get_queue_is_empty (manager->udev_queue)) {
                ply_trace ("udev coldplug completed already ");
                create_seats_from_udev (manager);
                return;
        }

        fd = inotify_init1 (IN_CLOEXEC);
        result = inotify_add_watch (fd, "/run/udev", IN_MOVED_TO| IN_DELETE);

        if (result < 0) {
                ply_trace ("could not watch for udev to show up: %m");
                close (fd);

                create_fallback_seat (manager);
                return;
        }

        manager->udev_queue_fd = fd;

        manager->udev_queue_fd_watch = ply_event_loop_watch_fd (manager->loop,
                                                                fd,
                                                                PLY_EVENT_LOOP_FD_STATUS_HAS_DATA,
                                                                (ply_event_handler_t)
                                                                on_udev_queue_changed,
                                                                NULL,
                                                                manager);
}

void
ply_device_manager_watch_seats (ply_device_manager_t      *manager,
                                ply_seat_added_handler_t   seat_added_handler,
                                ply_seat_removed_handler_t seat_removed_handler,
                                void                      *data)
{
        bool done_with_initial_seat_setup;

        manager->seat_added_handler = seat_added_handler;
        manager->seat_removed_handler = seat_removed_handler;
        manager->seat_event_handler_data = data;

        /* Try to create seats for each serial device right away, if possible
         */
        done_with_initial_seat_setup = create_seats_from_terminals (manager);

        if (done_with_initial_seat_setup)
                return;

        if ((manager->flags & PLY_DEVICE_MANAGER_FLAGS_IGNORE_UDEV)) {
                ply_trace ("udev support disabled, creating fallback seat");
                create_fallback_seat (manager);
                return;
        }

        watch_for_udev_events (manager);
        watch_for_coldplug_completion (manager);
}

bool
ply_device_manager_has_open_seats (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                if (ply_seat_is_open (seat))
                        return true;

                node = next_node;
        }

        return false;
}

ply_list_t *
ply_device_manager_get_seats (ply_device_manager_t *manager)
{
        return manager->seats;
}

ply_terminal_t *
ply_device_manager_get_default_terminal (ply_device_manager_t *manager)
{
        return manager->local_console_terminal;
}

void
ply_device_manager_activate_renderers (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        ply_trace ("activating renderers");
        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                ply_seat_activate_renderer (seat);

                node = next_node;
        }
}

void
ply_device_manager_deactivate_renderers (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        ply_trace ("deactivating renderers");
        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                ply_seat_deactivate_renderer (seat);

                node = next_node;
        }
}

void
ply_device_manager_activate_keyboards (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        ply_trace ("activating keyboards");
        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                ply_seat_activate_keyboard (seat);

                node = next_node;
        }
}

void
ply_device_manager_deactivate_keyboards (ply_device_manager_t *manager)
{
        ply_list_node_t *node;

        ply_trace ("deactivating keyboards");
        node = ply_list_get_first_node (manager->seats);
        while (node != NULL) {
                ply_seat_t *seat;
                ply_list_node_t *next_node;

                seat = ply_list_node_get_data (node);
                next_node = ply_list_get_next_node (manager->seats, node);

                ply_seat_deactivate_keyboard (seat);

                node = next_node;
        }
}
