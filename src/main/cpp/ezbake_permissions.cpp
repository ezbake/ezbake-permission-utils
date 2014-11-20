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

#include "ezbake_permissions.hpp"
#include "ezbake_permissions.h"

#include <algorithm>
#include <iterator>
#include <set>

#include "ezbakeBaseAuthorizations_types.h"
#include "ezbakeBasePermissions_types.h"
#include "ezbakeBaseVisibility_types.h"

#include "exception_to_error_string.hpp"
#include "ezbake_visibility.hpp"

using std::inserter;
using std::set;
using std::set_intersection;

using ezbake::base::thrift::AdvancedMarkings;
using ezbake::base::thrift::Authorizations;
using ezbake::base::thrift::PlatformObjectVisibilities;
using ezbake::base::thrift::Visibility;

using ezbake::evaluate_visibility_expression;

const uint32_t EZBAKE_NO_USER_PERMS = 0;

const uint32_t EZBAKE_ALL_USER_PERMS =
    EZBAKE_USER_PERM_READ |
    EZBAKE_USER_PERM_WRITE |
    EZBAKE_USER_PERM_MANAGE_VISIBILITY |
    EZBAKE_USER_PERM_DISCOVER;

namespace {
    bool sets_intersect(
            const set<int64_t> &s1,
            const set<int64_t> &s2) {
        set<int64_t> intersection;

        set_intersection(
                s1.begin(), s1.end(),
                s2.begin(), s2.end(),
                inserter(intersection, intersection.begin()));

        return !intersection.empty();
    }

    void check_platform_auth(
            EzBakeUserPermission perm_to_check,
            const set<int64_t> &platform_auth,
            const set<int64_t> &platform_vis,
            uint32_t &user_perms) {
        if (platform_vis.empty() || sets_intersect(platform_auth, platform_vis)) {
            user_perms |= perm_to_check;
        }
    }
}

uint32_t ezbake::get_user_permissions(
        const Authorizations &auths,
        const Visibility &visibility) {
    bool formal_auths_ok = evaluate_visibility_expression(
            auths.formalAuthorizations,
            visibility.formalVisibility);

    if (!formal_auths_ok) {
        return EZBAKE_NO_USER_PERMS; // Formal auths check failed
    }

    if (!visibility.__isset.advancedMarkings) {
        return EZBAKE_ALL_USER_PERMS; // No further visibility to check
    }

    const AdvancedMarkings &markings = visibility.advancedMarkings;

    bool external_comm_auths_ok = evaluate_visibility_expression(
            auths.externalCommunityAuthorizations,
            markings.externalCommunityVisibility);

    if (!external_comm_auths_ok) {
        return EZBAKE_NO_USER_PERMS; // External community auths check failed
    }

    if (!markings.__isset.platformObjectVisibility) {
        return EZBAKE_ALL_USER_PERMS; // No further visibility to check
    }

    const PlatformObjectVisibilities &pov = markings.platformObjectVisibility;
    const set<int64_t> &platform_auths = auths.platformObjectAuthorizations;
    uint32_t user_perms = EZBAKE_NO_USER_PERMS;

    if (pov.__isset.platformObjectReadVisibility) {
        check_platform_auth(
                EZBAKE_USER_PERM_READ,
                platform_auths,
                pov.platformObjectReadVisibility,
                user_perms);
    } else {
        user_perms |= EZBAKE_USER_PERM_READ;
    }

    if (pov.__isset.platformObjectWriteVisibility) {
        check_platform_auth(
                EZBAKE_USER_PERM_WRITE,
                platform_auths,
                pov.platformObjectWriteVisibility,
                user_perms);
    } else {
        user_perms |= EZBAKE_USER_PERM_WRITE;
    }

    if (pov.__isset.platformObjectManageVisibility) {
        check_platform_auth(
                EZBAKE_USER_PERM_MANAGE_VISIBILITY,
                platform_auths,
                pov.platformObjectManageVisibility,
                user_perms);
    } else {
        user_perms |= EZBAKE_USER_PERM_MANAGE_VISIBILITY;
    }

    if (pov.__isset.platformObjectDiscoverVisibility) {
        check_platform_auth(
                EZBAKE_USER_PERM_DISCOVER,
                platform_auths,
                pov.platformObjectDiscoverVisibility,
                user_perms);
    } else {
        user_perms |= EZBAKE_USER_PERM_DISCOVER;
    }

    return user_perms;
}

uint32_t ezbake_get_user_permissions(
        const authorizations_handle_t * const auths_handle,
        const visibility_handle_t * const visibility_handle,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(EZBAKE_NO_USER_PERMS, {
        if (visibility_handle == NULL) {
            return EZBAKE_ALL_USER_PERMS; // No visibility controls
        }

        if (auths_handle == NULL) {
            return EZBAKE_NO_USER_PERMS; // Has visibility controls but no auths
        }

        const Authorizations * const auths =
            static_cast<const Authorizations *>(auths_handle);

        const Visibility * const visibility =
            static_cast<const Visibility *>(visibility_handle);

        return ezbake::get_user_permissions(*auths, *visibility);
    })
}
