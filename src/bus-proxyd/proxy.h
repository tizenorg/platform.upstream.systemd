/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include "sd-bus.h"
#include "bus-message.h"
#include "bus-xml-policy.h"
#include "util.h"

typedef struct Proxy Proxy;

typedef struct BusCynara BusCynara;
typedef struct ProxyContext ProxyContext;
typedef struct PolicyMessageCheckHistory PolicyMessageCheckHistory; 

struct Proxy {
        sd_bus *local_bus;
        struct ucred local_creds;
        int local_in;
        int local_out;

        sd_bus *destination_bus;

        Set *owned_names;
        SharedPolicy *policy;

        ProxyContext *proxy_context;
        bool got_hello : 1;
};

int proxy_new(Proxy **out, int in_fd, int out_fd, BusCynara *cynara, const char *dest);
Proxy *proxy_free(Proxy *p);

int proxy_set_policy(Proxy *p, SharedPolicy *policy, char **configuration);
int proxy_hello_policy(Proxy *p, uid_t original_uid);
int proxy_run(Proxy *p);

int proxy_context_new(ProxyContext **pc, BusCynara *bus_cynara);
ProxyContext* proxy_context_free(ProxyContext *pc);

BusCynara* proxy_ref_bus_cynara(ProxyContext *pc);


DEFINE_TRIVIAL_CLEANUP_FUNC(Proxy*, proxy_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(ProxyContext*, proxy_context_free);


/*
 * function resturn message to send if there is no message to send it returns NULL 
 *
**/

sd_bus_message* proxy_dispatch_message_to_dest(Proxy *p, sd_bus_message *m, PolicyDeferredMessage *deferred);

sd_bus_message* proxy_dispatch_message_to_local(Proxy *p, sd_bus_message *m, PolicyDeferredMessage *deferred);
