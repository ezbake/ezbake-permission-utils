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

#include <exception>
#include <functional>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>

#include "ezbakeBaseAuthorizations_types.h"
#include "ezbakeBasePermissions_types.h"
#include "ezbakeBaseTypes_types.h"
#include "ezbakeBaseVisibility_types.h"

#include "ezbake_permissions.hpp"
#include "ezbake_purge.hpp"
#include "ezbake_serialization.hpp"
#include "ezbake_visibility.hpp"

#include "ezbake_permissions.h"
#include "ezbake_purge.h"
#include "ezbake_serialization.h"
#include "ezbake_visibility.h"

#include "exception_to_error_string.hpp"

using std::cerr;
using std::endl;
using std::exception;
using std::function;
using std::logic_error;
using std::set;
using std::string;
using std::stringstream;
using std::vector;

using ezbake::base::thrift::AdvancedMarkings;
using ezbake::base::thrift::Authorizations;
using ezbake::base::thrift::EzSecurityToken;
using ezbake::base::thrift::PlatformObjectVisibilities;
using ezbake::base::thrift::Visibility;

using ezbake::evaluate_visibility_expression;
using ezbake::get_user_permissions;
using ezbake::serialize_thrift_base64;
using ezbake::should_purge;

#define LOG_TEST() \
    std::cout << "Running " << __FUNCTION__ << std::endl;

#define ASSERT_EQUALS(expected, actual) \
    assert_equals((expected), (actual), __FUNCTION__, __LINE__);

#define ASSERT_EQUALS_NO_PRINT_DIFF(expected, actual) \
    assert_equals_no_print_diff((expected), (actual), __FUNCTION__, __LINE__);

#define ASSERT_ERROR(expected_error, actual_error) \
    assert_error((expected_error), (actual_error), __FUNCTION__, __LINE__);

#define ASSERT_NO_ERROR(error, context) \
    assert_no_error((error), __FUNCTION__, __LINE__, (context));

#define ASSERT_PERMS_EQUALS_C(auths, visibility, expected) \
    assert_perms_equals_c( \
            (auths), (visibility), (expected), __FUNCTION__, __LINE__);

template<typename T>
void assert_equals(
        const T &expected,
        const T &actual,
        const string &test_name,
        int line_num) {
    if (actual != expected) {
        stringstream str;
        str << "ERROR: In '" << test_name << "' at line " << line_num
            << ": Expected '" << expected << "', but got '" << actual << "'";

        throw logic_error(str.str());
    }
}

template<typename T>
void assert_equals_no_print_diff(
        const T &expected,
        const T &actual,
        const string &test_name,
        int line_num) {
    if (actual != expected) {
        stringstream str;
        str << "ERROR: Equals mismatch in '" << test_name << "' at line "
            << line_num;

        throw logic_error(str.str());
    }
}

void assert_error(
        const char *expected_error,
        char *actual_error,
        const string &test_name,
        int line_num) {
    if (actual_error == NULL) {
        stringstream str;
        str << "ERROR: In '" << test_name << "' at line " << line_num
            << ": Expected error did not occur: Expected '"
            << expected_error << "'";

        free(actual_error);
        throw logic_error(str.str());
    }

    if (strcmp(expected_error, actual_error) != 0) {
        stringstream str;
        str << "ERROR: In '" << test_name << "' at line " << line_num
            << ": Did not get expected error message: Expected '"
            << expected_error << "', but got '" << actual_error << "'";

        free(actual_error);
        throw logic_error(str.str());
    }
}

void assert_no_error(
        char *error,
        const string &test_name,
        int line_num,
        const string &context) {
    if (error != NULL) {
        stringstream str;
        str << "ERROR: In '" << test_name << "' at line " << line_num
            << ": Got C API error message when trying to " << context << ": "
            << error;

        free(error);
        throw logic_error(str.str());
    }
}

void assert_perms_equals_c(
        const Authorizations &auths,
        const Visibility &visibility,
        uint32_t expected,
        const string &test_name,
        int line_num) {
    char *error = NULL;

    char *visibility_base64 = serialize_thrift_base64(visibility);

    visibility_handle_t *visibility_handle =
        ezbake_deserialize_visibility_base64(visibility_base64, &error);

    free(visibility_base64);

    assert_no_error(error, test_name, line_num, "deserialize visibility");

    char *auths_base64 = serialize_thrift_base64(auths);

    authorizations_handle_t *auths_handle =
        ezbake_deserialize_authorizations_base64(auths_base64, &error);

    free(auths_base64);

    assert_no_error(error, test_name, line_num, "deserialize auths");

    uint32_t actual_perms = ezbake_get_user_permissions(
            auths_handle, visibility_handle, &error);

    assert_no_error(error, test_name, line_num, "get permissions");
    assert_equals(expected, actual_perms, test_name, line_num);

    ezbake_visibility_handle_free(visibility_handle);
    ezbake_authorizations_handle_free(auths_handle);
}

PlatformObjectVisibilities create_platform_obj_vis() {
    PlatformObjectVisibilities pov;
    pov.__set_platformObjectReadVisibility({56L, 2785L, 123876592237L});
    pov.__set_platformObjectWriteVisibility({2785L, 123876592237L});
    pov.__set_platformObjectDiscoverVisibility({3L, 56L, 2785L, 123876592237L});
    pov.__set_platformObjectManageVisibility({123876592237L});

    return pov;
}

AdvancedMarkings create_advanced_markings() {
    AdvancedMarkings markings;
    markings.__set_composite(true);
    markings.__set_externalCommunityVisibility("Foo&(Bar|Baz)");
    markings.__set_id(18657294732947L);
    markings.__set_platformObjectVisibility(create_platform_obj_vis());
    markings.__set_purgeIds({87L, 9723957L});

    return markings;
}

Visibility create_visibility() {
    Visibility visibility;
    visibility.__set_formalVisibility("TS&USA");
    visibility.__set_advancedMarkings(create_advanced_markings());

    return visibility;
}

EzSecurityToken create_security_token() {
    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});

    EzSecurityToken token;
    token.__set_authorizationLevel("authLevel");
    token.__set_authorizations(auths);
    token.__set_citizenship("USA");
    token.__set_organization("bestOrgEver");

    return token;
}

void test_get_permissions_all() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_ALL_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_read_discover() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({56L});

    uint32_t expected_perms =
        EZBAKE_USER_PERM_READ | EZBAKE_USER_PERM_DISCOVER;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_no_perms() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    // Add 1 to all positions
    auths.__set_platformObjectAuthorizations({4L, 57L, 2786L, 123876592238L});

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_external_community_mismatch() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_formal_auths_mismatch() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_visibility() {
    LOG_TEST();

    Visibility visibility;

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_ALL_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_auths() {
    LOG_TEST();

    Visibility visibility = create_visibility();
    Authorizations auths;

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_formal_visibility() {
    LOG_TEST();

    Visibility visibility = create_visibility();
    visibility.formalVisibility = "";
    visibility.__isset.formalVisibility = false;

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({56L});

    uint32_t expected_perms =
        EZBAKE_USER_PERM_READ | EZBAKE_USER_PERM_DISCOVER;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_formal_auths() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({56L});

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_markings() {
    LOG_TEST();

    Visibility visibility = create_visibility();
    visibility.advancedMarkings = AdvancedMarkings{};
    visibility.__isset.advancedMarkings = false;

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_ALL_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_platform_vis() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    visibility.advancedMarkings.platformObjectVisibility =
        PlatformObjectVisibilities{};

    visibility.advancedMarkings.__isset.platformObjectVisibility = false;

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});
    auths.__set_platformObjectAuthorizations({3L, 56L, 2785L, 123876592237L});

    uint32_t expected_perms = EZBAKE_ALL_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_get_permissions_empty_platform_auths() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    Authorizations auths;
    auths.__set_formalAuthorizations(set<string>{"U", "C", "S", "TS", "USA"});
    auths.__set_externalCommunityAuthorizations(set<string>{"Foo", "Bar"});

    uint32_t expected_perms = EZBAKE_NO_USER_PERMS;

    // C++ API
    ASSERT_EQUALS(expected_perms, get_user_permissions(auths, visibility));

    // C API
    ASSERT_PERMS_EQUALS_C(auths, visibility, expected_perms);
}

void test_validate_visibility_expression() {
    LOG_TEST();

    ASSERT_EQUALS(true, evaluate_visibility_expression(set<string>{}, ""));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(set<string>{"U", "C", "UK"}, ""));

    ASSERT_EQUALS(
            false, evaluate_visibility_expression(set<string>{}, "TS&USA"));

    ASSERT_EQUALS(
            false,
            evaluate_visibility_expression(
                set<string>{"U", "C", "UK"}, "TS&USA"));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(set<string>{"U", "C", "UK"}, "U"));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(
                set<string>{"U", "C", "S", "TS", "USA"}, "U"));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(
                set<string>{"U", "C", "S", "TS", "USA"}, "TS&USA"));

    ASSERT_EQUALS(
            false,
            evaluate_visibility_expression(
                set<string>{"U", "C", "S", "TS", "USA"}, "FOO"));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(
                set<string>{"U", "C", "S", "TS", "USA"}, "U|USA"));

    ASSERT_EQUALS(
            true,
            evaluate_visibility_expression(
                set<string>{"U", "C", "S", "TS"}, "U|USA"));

    ASSERT_EQUALS(
            false, evaluate_visibility_expression(
                set<string>{"C", "S", "TS"}, "TS&USA"));
}

void test_get_purge_info() {
    LOG_TEST();

    Visibility vis_composite = create_visibility();

    Visibility vis_singular = create_visibility();
    vis_singular.advancedMarkings.composite = false;

    // C API
    char *error = NULL;

    purge_info_t purge_info_true;
    ezbake_get_purge_info(&vis_composite, &purge_info_true, &error);
    ASSERT_NO_ERROR(error, "Getting purge info (composite = true)");
    ASSERT_EQUALS(true, purge_info_true.composite);
    ASSERT_EQUALS(18657294732947L, purge_info_true.id);

    purge_info_t purge_info_false;
    ezbake_get_purge_info(&vis_singular, &purge_info_false, &error);
    ASSERT_NO_ERROR(error, "Getting purge info (composite = false)");
    ASSERT_EQUALS(false, purge_info_false.composite);
    ASSERT_EQUALS(18657294732947L, purge_info_false.id);
}

void test_should_purge() {
    LOG_TEST();

    Visibility visibility = create_visibility();

    // C++ API
    ASSERT_EQUALS(true, should_purge({5L, 18657294732947L}, visibility));
    ASSERT_EQUALS(false, should_purge({5L, 762L}, visibility));

    // C API
    const int64_t with_id[] = {5L, 18657294732947L};
    const int64_t without_id[] = {5L, 762L};

    char *error = NULL;

    bool actual_with = ezbake_should_purge(with_id, 2, &visibility, &error);
    ASSERT_NO_ERROR(error, "Checking purge with match");
    ASSERT_EQUALS(true, actual_with);

    bool actual_without =
        ezbake_should_purge(without_id, 2, &visibility, &error);

    ASSERT_NO_ERROR(error, "Checking purge without match");
    ASSERT_EQUALS(false, actual_without);
}

void test_token_serialize_roundtrip() {
    LOG_TEST();

    EzSecurityToken token = create_security_token();
    char *token_base64 = serialize_thrift_base64(token);
    char *error = NULL;

    token_handle_t *token_handle =
        ezbake_deserialize_token_base64(token_base64, &error);

    ASSERT_NO_ERROR(error, "Deserializing security token");

    EzSecurityToken *token_roundtrip =
        static_cast<EzSecurityToken *>(token_handle);

    ASSERT_EQUALS_NO_PRINT_DIFF(token, *token_roundtrip);

    ezbake_token_handle_free(token_handle);
}

void test_token_get_auths() {
    LOG_TEST();

    EzSecurityToken token = create_security_token();
    char *token_base64 = serialize_thrift_base64(token);
    char *error = NULL;

    token_handle_t *token_handle =
        ezbake_deserialize_token_base64(token_base64, &error);

    ASSERT_NO_ERROR(error, "Deserializing security token");

    authorizations_handle_t *auths =
        ezbake_get_authorizations_from_token(token_handle, &error);

    ASSERT_NO_ERROR(error, "Getting auths from security token");

    Authorizations *auths_roundtrip = static_cast<Authorizations *>(auths);

    ASSERT_EQUALS_NO_PRINT_DIFF(token.authorizations, *auths_roundtrip);

    ezbake_token_handle_free(token_handle);
    ezbake_authorizations_handle_free(auths);
}

int possible_failing(int n) {
    if (n == 0) {
        throw logic_error("n = 0");
    }

    if (n == 1) {
        throw 5;
    }

    return n;
}

int possible_failing_c_wrapper(int n, char **error) {
    EXCEPTION_TO_ERROR_STRING(-1, {
        return possible_failing(n);
    })
}

void test_exception_to_error_string() {
    LOG_TEST();

    char *error = NULL;

    int should_work = possible_failing_c_wrapper(5, &error);
    ASSERT_NO_ERROR(error, "Calling wrapper that should work");
    ASSERT_EQUALS(5, should_work);

    int fail1 = possible_failing_c_wrapper(0, &error);
    ASSERT_ERROR("n = 0", error);
    ASSERT_EQUALS(-1, fail1);
    error = NULL;

    int fail2 = possible_failing_c_wrapper(0, NULL);
    ASSERT_EQUALS(-1, fail2);
    error = NULL;

    int fail3 = possible_failing_c_wrapper(1, &error);
    ASSERT_ERROR("Unknown error occurred", error);
    ASSERT_EQUALS(-1, fail3);
    error = NULL;

    int fail4 = possible_failing_c_wrapper(1, NULL);
    ASSERT_EQUALS(-1, fail4);
    error = NULL;
}

const vector<function<void()>> TEST_FUNCS = {
    test_get_permissions_all,
    test_get_permissions_read_discover,
    test_get_permissions_no_perms,
    test_get_permissions_external_community_mismatch,
    test_get_permissions_formal_auths_mismatch,
    test_get_permissions_empty_visibility,
    test_get_permissions_empty_auths,
    test_get_permissions_empty_formal_visibility,
    test_get_permissions_empty_formal_auths,
    test_get_permissions_empty_markings,
    test_get_permissions_empty_platform_vis,
    test_get_permissions_empty_platform_auths,
    test_validate_visibility_expression,
    test_get_purge_info,
    test_should_purge,
    test_token_serialize_roundtrip,
    test_token_get_auths,
    test_exception_to_error_string
};

int main() {
    int num_errors = 0;

    auto func_iter = TEST_FUNCS.cbegin();
    for (; func_iter != TEST_FUNCS.cend(); ++func_iter) {
        try {
            (*func_iter)();
        } catch (const exception &e) {
            cerr << e.what() << endl;
            num_errors++;
        } catch (...) {
            cerr << "ERROR: Unknown error" << endl;
            num_errors++;
        }
    }

    return num_errors;
}
