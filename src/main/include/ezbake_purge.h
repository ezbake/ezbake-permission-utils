/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#ifndef EZBAKE_PURGE_H
#define EZBAKE_PURGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

#include "ezbake_serialization.h"

typedef struct {
    bool composite;
    int64_t id;
} purge_info_t;

void ezbake_get_purge_info(
        const visibility_handle_t * const visibility_handle,
        purge_info_t *purge_info,
        char **error);

bool ezbake_should_purge(
        const int64_t * const ids_to_purge,
        size_t ids_length,
        const visibility_handle_t * const visibility_handle,
        char **error);

#ifdef __cplusplus
}
#endif

#endif
