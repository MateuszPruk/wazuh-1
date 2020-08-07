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
#include "../../unit_tests/analysisd/mocks_os_analysisd.h"

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_pthread_mutex_init() {
    return mock();
}

int __wrap_pthread_mutex_lock() {
    return mock();
}

int __wrap_pthread_mutex_unlock() {
    return mock();
}

int __wrap_pthread_mutex_destroy() {
    return mock();
}

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    if (!logtest_enabled) {
        w_logtest_conf.enabled = false;
    }
    return mock();
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size) {
    if (new_size) check_expected(new_size);
    return mock();
}

OSList *__wrap_OSList_Create() {
    return mock_type(OSList *);
}

int __wrap_OSList_SetMaxSize() {
    return mock();
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap_w_mutex_init() {
    return;
}

void __wrap_w_mutex_destroy() {
    return;
}

void __wrap_w_create_thread() {
    return;
}

int __wrap_close (int __fd) {
    return mock();
}

int __wrap_getDefine_Int() {
    return mock();
}

void * __wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

void __wrap_os_remove_rules_list(RuleNode *node) {
    return;
}

void * __wrap_OSHash_Free(OSHash *self) {
    return mock_type(void *);
}

void __wrap_os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn) {
    return;
}

void __wrap_os_remove_cdblist(ListNode **l_node) {
    return;
}

void __wrap_os_remove_cdbrules(ListRule **l_rule) {
    return;
}

void __wrap_os_remove_eventlist(EventList *list) {
    return;
}

unsigned int __wrap_sleep (unsigned int __seconds) {
    return mock_type(unsigned int);
}

OSHashNode *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i) {
    return mock_type(OSHashNode *);
}

time_t __wrap_time(time_t *t) {
    return mock_type(time_t);
}

double __wrap_difftime (time_t __time1, time_t __time0) {
    return mock();
}

OSHashNode *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current) {
    return mock_type(OSHashNode *);
}
