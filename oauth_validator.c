#include <string.h>

#include "postgres.h"

#include "token_utils.h"

#include "fmgr.h"
#include "libpq/oauth.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

/*
 * Declarations of internal module functions.
 */
static void validator_startup(ValidatorModuleState *state);
static void validator_shutdown(ValidatorModuleState *state);
static bool validate_token(const ValidatorModuleState *state,
                           const char *token,
                           const char *role,
                           ValidatorModuleResult *result);

/*
 * Structure with pointers to OAuth token validator callback functions.
 * PostgreSQL calls these functions during certain phases of the module's lifecycle.
 */
static const OAuthValidatorCallbacks validator_callbacks = {
    PG_OAUTH_VALIDATOR_MAGIC, /* Magic number for API version check */

    .startup_cb = validator_startup,   /* Validator initialization function */
    .shutdown_cb = validator_shutdown, /* Validator shutdown function */
    .validate_cb = validate_token      /* Token validation function */
};

/*
 * Entry point for the OAuth validator module.
 * PostgreSQL calls this function when loading the module.
 */
const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
    return &validator_callbacks;
}

/*
 * Validator initialization function.
 * Called once when the module is loaded.
 */
static void
validator_startup(ValidatorModuleState *state)
{
    /*
     * Check if the server version matches the one the module was built with.
     * (Real production modules shouldn't do this, as it breaks upgrade compatibility.)
     */
    if (state->sversion != PG_VERSION_NUM)
        elog(ERROR, "oauth_validator: server version mismatch: sversion=%d", state->sversion);
}

/*
 * Validator shutdown function.
 * Called when the module is unloaded or the server shuts down.
 */
static void
validator_shutdown(ValidatorModuleState *state)
{
    /* Nothing to do for now, but resource cleanup could be added here if necessary. */
}

/*
 * Main OAuth token validation function.
 *
 * Parameters:
 * - state: validator module state (may contain configuration etc.);
 * - token: string containing the token to validate;
 * - role: PostgreSQL role the client is trying to connect as;
 * - res: structure to store the validation result.
 *
 * Returns true if the token is valid, false otherwise.
 */
static bool
validate_token(const ValidatorModuleState *state,
               const char *token, const char *role,
               ValidatorModuleResult *res)
{
    char *sub = NULL;               /* Value of the "sub" field from the token (user identifier) */
    char *scope = NULL;             /* Value of the "scope" field from the token (allowed scopes) */
    const char *token_payload = NULL; /* Token payload as JSON string */
    List *granted_scopes = NIL;     /* List of scopes granted by the token */
    List *required_scopes = NIL;    /* List of required scopes from HBA configuration */
    bool matched = false;           /* Flag indicating whether required scopes are satisfied */

    /* Initialize result */
    res->authn_id = NULL;     /* Authentication ID (sub) */
    res->authorized = false;  /* Authorization flag */

    /* Extract payload from the token */
    token_payload = parse_token_payload(token);
    if (token_payload == NULL)
    {
        elog(LOG, "Invalid token: missing payload: %s", token);
        return false;
    }

    /* Extract 'sub' and 'scope' fields from the payload */
    extract_sub_scope_fields(token_payload, &sub, &scope);
    if (!sub || !scope)
    {
        elog(LOG, "Invalid token: missing sub and/or scope fields: %s", token);
        return false;
    }

    /* Set authentication ID (sub) in the result */
    res->authn_id = pstrdup(sub);

    /* Split the token's scope field into a list */
    granted_scopes = split_scopes(scope);

    /* Split the required scopes from HBA file into a list */
    required_scopes = split_scopes(MyProcPort->hba->oauth_scope);

    if (!granted_scopes || !required_scopes)
        return false;

    /* Check if the granted scopes satisfy the required scopes */
    matched = check_scopes(granted_scopes, required_scopes);

    /* Set authorization result flag */
    res->authorized = matched;

    return true;
}
