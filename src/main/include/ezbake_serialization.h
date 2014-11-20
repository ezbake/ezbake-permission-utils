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

#ifndef EZBAKE_SERIALIZATION_H
#define EZBAKE_SERIALIZATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef void visibility_handle_t;
typedef void authorizations_handle_t;
typedef void token_handle_t;

visibility_handle_t *ezbake_deserialize_visibility_binary(
        const uint8_t * const visibility_binary,
        size_t visibility_binary_length,
        char **error);

visibility_handle_t *ezbake_deserialize_visibility_base64(
        const char * const visibility_base64,
        char **error);

void ezbake_visibility_handle_free(visibility_handle_t *handle);

authorizations_handle_t *ezbake_deserialize_authorizations_binary(
        const uint8_t * const authorizations_binary,
        size_t authorizations_binary_length,
        char **error);

authorizations_handle_t *ezbake_deserialize_authorizations_base64(
        const char * const authorizations_base64,
        char **error);

void ezbake_authorizations_handle_free(authorizations_handle_t *handle);

token_handle_t *ezbake_deserialize_authorizations_binary(
        const uint8_t * const token_binary,
        size_t token_binary_length,
        char **error);

token_handle_t *ezbake_deserialize_token_base64(
        const char * const token_base64,
        char **error);

void ezbake_token_handle_free(token_handle_t *handle);

authorizations_handle_t *ezbake_get_authorizations_from_token(
        const token_handle_t *token,
        char **error);

#ifdef __cplusplus
}
#endif

#endif
