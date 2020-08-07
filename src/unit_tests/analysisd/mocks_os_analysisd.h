/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size);

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len);

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...);

int __wrap_pthread_mutex_init();

int __wrap_pthread_mutex_lock();

int __wrap_pthread_mutex_unlock();

int __wrap_pthread_mutex_destroy();

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2);

OSHash *__wrap_OSHash_Create();

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size);

OSList *__wrap_OSList_Create();

int __wrap_OSList_SetMaxSize();

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...);

void __wrap_w_mutex_init();

void __wrap_w_mutex_destroy();

void __wrap_w_create_thread();

int __wrap_close (int __fd);

int __wrap_getDefine_Int();

void * __wrap_OSHash_Delete_ex(OSHash *self, const char *key);

void __wrap_os_remove_rules_list(RuleNode *node);

void * __wrap_OSHash_Free(OSHash *self);

void __wrap_os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn);

void __wrap_os_remove_cdblist(ListNode **l_node);

void __wrap_os_remove_cdbrules(ListRule **l_rule);

void __wrap_os_remove_eventlist(EventList *list);

unsigned int __wrap_sleep (unsigned int __seconds);

OSHashNode *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i);

time_t __wrap_time(time_t *t);

double __wrap_difftime (time_t __time1, time_t __time0);

OSHashNode *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current);
