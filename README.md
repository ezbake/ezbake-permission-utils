# Permission Utils
A library to handle generating user permissions given a visibility and user authorizations.

The below code in Java, C, and C++ shows the main use case of calculating permissions given user authorizations and
data visibility.

## Java API

```java
package example;

import java.util.EnumSet;
import java.util.Set;

import org.apache.thrift.TException;

import ezbake.base.thrift.Authorizations;
import ezbake.base.thrift.EzSecurityToken;
import ezbake.base.thrift.Permission;
import ezbake.base.thrift.Visibility;
import ezbake.security.permissions.PermissionUtils;
import ezbake.thrift.ThriftUtils;

public class Example {
    public static void main(String[] args) {
        // Get actual EzSecurityToken from Thrift call, etc.
        final EzSecurityToken securityToken = new EzSecurityToken();

        // Get actual serialized Visibility struct from backend (could be either Base64-encoded string or raw bytes)
        final String visibilityBase64 = "foobarbaz";

        Visibility visibility = null;
        try {
            // Convert serialized Visibility to actual struct
            visibility = ThriftUtils.deserializeFromBase64(Visibility.class, visibilityBase64);
            // NOTE: or use ThriftUtils.deserialize(Visibility.class, visibilityBytes) if using raw bytes
        } catch (final TException e) {
            // Handle error in some way
        }

        // Get Authorizations instance from EzSecurityToken
        final Authorizations userAuths = securityToken.getAuthorizations();

        // NOTE: There are overloads of gerPermissions to skip various checks like formal authorization.
        final Set<Permission> userPerms = PermissionUtils.getPermissions(userAuths, visibility);
        if (userPerms.contains(Permission.READ) && userPerms.contains(Permission.WRITE)) {
            // Allow data read with update
        } else if (userPerms.containsAll(EnumSet.of(Permission.READ, Permission.DISCOVER))) {
            // Another way to check multiple permissions
        }

        // You can also use the overload of getPermissions that takes a subset of perms you care about so that all do
        // not have to be calculated
        final Set<Permission> userPerms2 =
                PermissionUtils.getPermissions(userAuths, visibility, true, EnumSet.of(Permission.READ));
        if (!userPerms2.isEmpty()) {
            // Allow read operations
        }
    }
}
```

## C API

```c
#include <stdio.h>
#include <stdlib.h>

#include "ezbake_permissions.h"
#include "ezbake_serialization.h"

int main() {
    char *error = NULL;

    /* Base64-encoded Thrift-serialized Visibility struct */
    char *visibility_base64 = /* Get from backend */;

    /* Can use ezbake_deserialize_visibility_binary if you have a non-encoded
       binary array */
    visibility_handle_t *visibility_handle =
        ezbake_deserialize_visibility_base64(visibility_base64, &error);

    free(visibility_base64); /* Assuming pointer was malloc'ed */

    if (error != NULL) {
        fprintf(stderr, "ERROR: %s\n", error);
        free(error);
        return 1;
    }

    /* Base64-encoded Thrift-serialized Authorizations struct */
    char *auths_base64 = /* Get from request, etc. */;

    /* Can use ezbake_deserialize_authorizations_binary if you have a
       non-encoded binary array */
    authorizations_handle_t *auths_handle =
        ezbake_deserialize_authorizations_base64(auths_base64, &error);

    free(auths_base64); /* Assuming pointer was malloc'ed */

    if (error != NULL) {
        fprintf(stderr, "ERROR: %s\n", error);
        free(error);
        return 1;
    }

    uint32_t user_perms = ezbake_get_user_permissions(
            auths_handle, visibility_handle, &error);

    if (error != NULL) {
        fprintf(stderr, "ERROR: %s\n", error);
        free(error);
        return 1;
    }

    if ((user_perms & EZBAKE_USER_PERM_READ) || (user_perms & EZBAKE_USER_PERM_DISCOVER)) {
        printf("User has read or discover permissions!\n");
    }

    ezbake_visibility_handle_free(visibility_handle);
    ezbake_authorizations_handle_free(auths_handle);

    return 0;
}
```

## C++ API

```cpp
#include <exception>
#include <iostream>

#include "ezbakeBaseAuthorizations_types.h"
#include "ezbakeBaseVisibility_types.h"

#include "ezbake_permissions.hpp"
#include "ezbake_serialization.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::exception;
using std::string;

using ezbake::deserialize_thrift;
using ezbake::get_user_permissions;

using ezbake::base::thrift::Authorizations;
using ezbake::base::thrift::Visibility;

int main() {
    // Base64-encoded Thrift-serialized Visibility struct
    string visibility_base64 = /* Get from backend */;

    // Base64-encoded Thrift-serialized Authorizations struct
    string auths_base64 = /* Get from request, etc. */;

    try {
        Visibility visibility;
        deserialize_thrift(visibility_base64, visibility);
    } catch (const exception &e) {
        // Handle error in some way
        cerr << "ERROR: " << e.what() << endl;
        return 1;
    }

    try {
        Authorizations auths;
        deserialize_thrift(auths_base64, auths);
    } catch (const exception &e) {
        // Handle error in some way
        cerr << "ERROR: " << e.what() << endl;
        return 1;
    }

    uint32_t user_perms = get_user_permissions(auths, visibility);

    if ((user_perms & EZBAKE_USER_PERM_READ) || (user_perms & EZBAKE_USER_PERM_DISCOVER)) {
        cout << "User has read or discover permissions!" << endl;
    }

    return 0;
}
```
