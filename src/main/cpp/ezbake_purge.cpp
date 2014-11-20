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

#include "ezbake_purge.hpp"
#include "ezbake_purge.h"

#include "ezbakeBaseVisibility_types.h"

#include "exception_to_error_string.hpp"

using std::set;
using ezbake::base::thrift::Visibility;

bool ezbake::should_purge(
        const set<int64_t> &ids_to_purge, const Visibility &visibility) {
    if (!visibility.__isset.advancedMarkings ||
            !visibility.advancedMarkings.__isset.id) {
        return false;
    }

    return ids_to_purge.count(visibility.advancedMarkings.id) != 0;
}

void ezbake_get_purge_info(
        const visibility_handle_t * const visibility_handle,
        purge_info_t *purge_info,
        char **error) {
    if (visibility_handle == NULL) {
        *error = strdup("Visibility handle cannot be null");
        return;
    }

    if (purge_info == NULL) {
        *error = strdup("Purge info out parameter cannot be null");
        return;
    }

    const Visibility *visibility =
        static_cast<const Visibility *>(visibility_handle);

    purge_info->composite = visibility->advancedMarkings.composite;
    purge_info->id = visibility->advancedMarkings.id;
}

bool ezbake_should_purge(
        const int64_t * const ids_to_purge,
        size_t ids_length,
        const visibility_handle_t * const visibility_handle,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(false, {
        if (ids_to_purge == NULL || ids_length == 0) {
            return false;
        }

        set<int64_t> purge_ids;
        for (size_t i = 0; i < ids_length; ++i) {
            purge_ids.insert(ids_to_purge[i]);
        }

        const Visibility *visibility =
            static_cast<const Visibility *>(visibility_handle);

        return ezbake::should_purge(purge_ids, *visibility);
    })
}
