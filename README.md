# OAuth 2.0 token validator for PostgreSQL

## Overview

This module implements a simple OAuth 2.0 token validator for built-in support of the **Device Authorization Flow**. The validator performs minimal validation by:

* Extracting the `sub` (subject) and `scope` fields from the JWT payload.
* Comparing the token's scopes with those required by the `pg_hba.conf` entry.
* Mapping the authenticataion identity `sub` to a database role using `pg_ident.conf`.
* Allowing or denying access based on matching of sub and scope.

---

## Requirements
* PostgreSQL >= 18 configured with `--with-libcurl` flag

---

## Compilation and installation

1. Compile and install the validator dynamic library.

For this run the following commands in the main directory:

```bash
make
make install
```

Validator will be installed in the `<postgres>/lib` directory under filename `oauth_validator.so`

2. Add the validator in the `postgresql.conf` to the setting `oauth_validator_libraries`:

```
oauth_validator_libraries='oauth_validator'
```

3. Configure the config file `pg_ident.conf`

For example:

```
# MAPNAME    SYSTEM-USERNAME                           PG-USERNAME
oauthmap    "7cf5b11f-adb2-4e67-83b7-5c75f7f1e6ee"     "mydbuser"
```

4. Configure the config file `pg_hba.conf`

For example:

```
local    all    all    oauth issuer="https://<address>/.well-known/openid-configuration" scope="openid postgres" map="oauthmap"
```

---

## Configs
* `posgtresql.conf` must contain validator module in `oauth_validator_libraries` entry
* `pg_hba.conf` must specify `oauth` as the authentication method and define `oauth_scope`
* `pg_ident.conf` must contain mappings between JWT sub values and PostgreSQL roles.

### Example of pg_ident.conf entry

```conf
# MAPNAME    SYSTEM-USERNAME                           PG-USERNAME
oauthmap    "7cf5b11f-adb2-4e67-83b7-5c75f7f1e6ee"     "mydbuser"
```

If the token contains `sub` value "7cf5b11f-adb2-4e67-83b7-5c75f7f1e6ee", and validation passes, PostgreSQL will map "7cf5b11f-adb2-4e67-83b7-5c75f7f1e6ee" to the mydbuser role using the oauthmap entry.

### Example of `pg_hba.conf` entry

```conf
local    all    all    oauth issuer="https://<address>/.well-known/openid-configuration" scope="openid postgres" map="oauthmap"
```

---

## Token Validation Logic

The core validation logic is implemented through the `validate_token` function. It performs the following steps:

1. **Parsing the token payload**
   The raw token string is parsed to extract its payload.
   If the token is malformed or the payload cannot be extracted, validation fails.

2. **Extracting JWT claims: `sub` and `scope`**
   The payload must contain both:

   * `sub`: Subject (used to identify the user)
   * `scope`: Space-separated list of scopes granted by the token

   If either field is missing, validation fails.

3. **Comparing scopes**
   The scopes from the entry `oauth_scope` in `pg_hba.conf` are compared with the scopes granted by the token.
   If some are missing in the token, validation fails.

   In the above configs example, validation is succesfull if the token contains both `openid` and `postgres` scopes.

4. **Setting authorization result**
   The `res->authorized` flag is set to `true` if scopes match, otherwise `false`.

5. **Assigning authentication identity**
   The `sub` value is assigned to `res->authn_id`, which PostgreSQL uses to identify the authenticated user.

6. **Assigning authentication identity**
   This `sub` value is then matched outside of this module against entries in `pg_ident.conf` to determine the actual database role the user is allowed to assume.

   If matching fails, validation fails.

7. Otherwise validation is succesfull and the client is authorized and succesfully connected to the database.

---

## Extensibility

This basic implementation can be extended with additional checks or custom logic, such as:

* Validating token signatures
* Validating token expiration (`exp`)
* Validating audience (`aud`) or issuer (`iss`)
* Fetching user roles dynamically
