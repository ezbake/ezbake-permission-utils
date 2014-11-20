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

#ifndef EZBAKE_PERMISSIONS_H
#define EZBAKE_PERMISSIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "ezbake_serialization.h"

typedef enum {
    EZBAKE_USER_PERM_READ = (1u << 0),
    EZBAKE_USER_PERM_WRITE = (1u << 1),
    EZBAKE_USER_PERM_MANAGE_VISIBILITY = (1u << 2),
    EZBAKE_USER_PERM_DISCOVER = (1u << 3)
} EzBakeUserPermission;

extern const uint32_t EZBAKE_NO_USER_PERMS;
extern const uint32_t EZBAKE_ALL_USER_PERMS;

uint32_t ezbake_get_user_permissions(
        const authorizations_handle_t * const auths_handle,
        const visibility_handle_t * const visibility_handle,
        char **error);

#ifdef __cplusplus
}
#endif

#endif
