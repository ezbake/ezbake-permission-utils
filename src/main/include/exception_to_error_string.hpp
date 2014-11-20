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

#ifndef EXCEPTION_TO_ERROR_STRING_HPP
#define EXCEPTION_TO_ERROR_STRING_HPP

#include <cstring>

#include <exception>

#define EXCEPTION_TO_ERROR_STRING(fail_return_val, code) \
    try { \
        code \
    } catch (const std::exception &e) { \
        if (error != NULL) { \
            *error = strdup(e.what()); \
        } \
        return (fail_return_val); \
    } catch (...) { \
        if (error != NULL) { \
            *error = strdup("Unknown error occurred"); \
        } \
        return (fail_return_val); \
    }

#endif
