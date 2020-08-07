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
#include "../../analysisd/rules.h"
#include "../../analysisd/cdb/cdb.h"
#include "../../analysisd/analysisd.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* setup/teardown */



/* wraps */

/* tests */

/* os_remove_cdblist */
void test_os_remove_cdblist_OK(void **state)
{
    ListNode **l_node;
    os_calloc(1,sizeof(ListNode *), l_node);
    os_calloc(1,sizeof(ListNode), l_node[0]);
    os_calloc(1,sizeof(ListNode), l_node[0]->cdb_filename);
    os_calloc(1,sizeof(char), l_node[0]->txt_filename);
    
    os_remove_cdblist(l_node);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_cdblist
        cmocka_unit_test(test_os_remove_cdblist_OK)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
