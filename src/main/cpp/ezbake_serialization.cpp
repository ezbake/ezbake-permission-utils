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

#include "ezbake_serialization.hpp"
#include "ezbake_serialization.h"

#include <memory>

#include "ezbakeBaseAuthorizations_types.h"
#include "ezbakeBasePermissions_types.h"
#include "ezbakeBaseTypes_types.h"
#include "ezbakeBaseVisibility_types.h"

#include "exception_to_error_string.hpp"

using std::unique_ptr;

using ezbake::base::thrift::AdvancedMarkings;
using ezbake::base::thrift::Authorizations;
using ezbake::base::thrift::EzSecurityToken;
using ezbake::base::thrift::PlatformObjectVisibilities;
using ezbake::base::thrift::Visibility;

using ezbake::deserialize_thrift;

visibility_handle_t *ezbake_deserialize_visibility_binary(
        const uint8_t * const visibility_binary,
        size_t visibility_binary_length,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<Visibility> vis{new Visibility()};

        deserialize_thrift(
                visibility_binary, visibility_binary_length, *vis);

        return vis.release();
    })
}

visibility_handle_t *ezbake_deserialize_visibility_base64(
        const char * const visibility_base64,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<Visibility> vis{new Visibility()};
        deserialize_thrift(visibility_base64, *vis);
        return vis.release();
    })
}

void ezbake_visibility_handle_free(visibility_handle_t *handle) {
    delete static_cast<Visibility *>(handle);
}

authorizations_handle_t *ezbake_deserialize_authorizations_binary(
        const uint8_t * const authorizations_binary,
        size_t authorizations_binary_length,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<Authorizations> auths{new Authorizations()};

        deserialize_thrift(
                authorizations_binary, authorizations_binary_length, *auths);

        return auths.release();
    })
}

authorizations_handle_t *ezbake_deserialize_authorizations_base64(
        const char * const authorizations_base64,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<Authorizations> auths{new Authorizations()};
        deserialize_thrift(authorizations_base64, *auths);
        return auths.release();
    })
}

void ezbake_authorizations_handle_free(authorizations_handle_t *handle) {
    delete static_cast<Authorizations *>(handle);
}

token_handle_t *ezbake_deserialize_token_binary(
        const uint8_t * const token_binary,
        size_t token_binary_length,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<EzSecurityToken> token{new EzSecurityToken()};
        deserialize_thrift(token_binary, token_binary_length, *token);
        return token.release();
    })
}

token_handle_t *ezbake_deserialize_token_base64(
        const char * const token_base64,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        unique_ptr<EzSecurityToken> token{new EzSecurityToken()};
        deserialize_thrift(token_base64, *token);
        return token.release();
    })
}

void ezbake_token_handle_free(token_handle_t *handle) {
    delete static_cast<EzSecurityToken *>(handle);
}

authorizations_handle_t *ezbake_get_authorizations_from_token(
        const token_handle_t *token_handle,
        char **error) {
    EXCEPTION_TO_ERROR_STRING(NULL, {
        const EzSecurityToken *token =
            static_cast<const EzSecurityToken *>(token_handle);

        unique_ptr<Authorizations> auths{new Authorizations(
                token->authorizations)};

        return auths.release();
    })
}
