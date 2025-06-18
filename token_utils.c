#include "postgres.h"

#include "token_utils.h"

#include "common/base64.h"
#include "mb/pg_wchar.h"

#define SUB_FIELD   0   /* Index for 'sub' field */
#define SCOPE_FIELD 1   /* Index for 'scope' field */

/*
 * JSON object field handler.
 * Marks that the currently processed field is 'sub' or 'scope'
 * to store its value at the next processing stage.
 */
static JsonParseErrorType
token_field_start(void *state, char *fname, bool isnull)
{
    char **fields = (char **) state;

    if (strcmp(fname, "sub") == 0)
        fields[SUB_FIELD] = (char *) 1;  /* Mark that we are processing 'sub' field */
    else if (strcmp(fname, "scope") == 0)
        fields[SCOPE_FIELD] = (char *) 1; /* Mark that we are processing 'scope' field */

    return JSON_SUCCESS;
}

/*
 * JSON scalar value handler.
 * Stores the value of 'sub' or 'scope' if it was marked earlier.
 */
static JsonParseErrorType
token_scalar(void *state, char *token, JsonTokenType tokentype)
{
    char **fields = (char **) state;

    if (fields[SUB_FIELD] == (char *) 1)
        fields[SUB_FIELD] = pstrdup(token);  /* Save the value of 'sub' */
    else if (fields[SCOPE_FIELD] == (char *) 1)
        fields[SCOPE_FIELD] = pstrdup(token); /* Save the value of 'scope' */

    return JSON_SUCCESS;
}

/*
 * Extracts 'sub' and 'scope' fields from a JSON string.
 *
 * Parameters:
 *  - json: JSON string
 *  - sub_field: returns the value of 'sub' field
 *  - scope_field: returns the value of 'scope' field
 */
void
extract_sub_scope_fields(const char *json, char **sub_field, char **scope_field)
{
    JsonLexContext lex;
    JsonSemAction sem;

    char **fields = palloc0(sizeof(char *) * 2); /* Allocate memory for 2 strings ('sub', 'scope') */

    *sub_field = NULL;
    *scope_field = NULL;

    /* Create a lexical context for JSON parsing */
    makeJsonLexContextCstringLen(&lex, json, strlen(json), GetDatabaseEncoding(), true);

    /* Set up JSON parser handlers */
    memset(&sem, 0, sizeof(sem));
    sem.semstate = (void *) fields;
    sem.object_field_start = token_field_start;
    sem.scalar = token_scalar;

    /* Start JSON parsing */
    pg_parse_json(&lex, &sem);

    /* Return the found values */
    *sub_field = fields[SUB_FIELD];
    *scope_field = fields[SCOPE_FIELD];
}

/*
 * Extracts the payload from a JWT token.
 * Returns the decoded payload string in JSON format.
 */
const char*
parse_token_payload(const char *token)
{
    char *dot1 = NULL;
    char *dot2 = NULL;
    int payload_len = 0;
    char *payload_b64url = NULL;
    char *b64 = NULL;

    if(!token)
        return NULL;

    /* Find the first and second dots in JWT (separators for header.payload.signature) */
    dot1 = strchr(token, '.');
    dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;

    if (!dot1 || !dot2)
    {
        elog(LOG, "Invalid token format, two dots required: %s", token);
        return NULL;
    }

    /* Extract the encoded payload between the dots */
    payload_len = dot2 - (dot1 + 1);
    payload_b64url = pnstrdup(dot1 + 1, payload_len);

    /* Convert base64url to regular base64 */
    b64 = base64url_to_base64(payload_b64url);

    /* Decode base64 to JSON string */
    return decode_base64(b64);
}

/*
 * Converts a base64url string to base64 format.
 * Replaces '-' with '+', '_' with '/' and adds padding '=' if necessary.
 */
char *
base64url_to_base64(const char *b64url)
{
    int len = strlen(b64url);
    int pad = (4 - (len % 4)) % 4; /* Determine the number of '=' padding characters */
    char *b64 = palloc(len + pad + 1);

    for (int i = 0; i < len; i++)
    {
        if (b64url[i] == '-')
            b64[i] = '+';
        else if (b64url[i] == '_')
            b64[i] = '/';
        else
            b64[i] = b64url[i];
    }

    /* Add padding '=' */
    for (int i = 0; i < pad; i++)
        b64[len + i] = '=';

    b64[len + pad] = '\0';
    return b64;
}

/*
 * Decodes a base64 string into a regular string.
 * Returns the decoded string or NULL in case of error.
 */
const char *
decode_base64(const char *b64)
{
    int encoded_len = strlen(b64);
    int max_decoded_len = pg_b64_dec_len(encoded_len); /* Calculate required buffer length */
    char *decoded = palloc(max_decoded_len + 1);
    int decoded_len = pg_b64_decode(b64, encoded_len, decoded, max_decoded_len);

    if (decoded_len <= 0)
    {
        elog(LOG, "Invalid token format: base64 decoding error");
        return NULL;
    }

    decoded[decoded_len] = '\0';
    return decoded;
}

/*
 * Splits a space-separated string (e.g., scope list from token) into a List of strings.
 */
List *
split_scopes(const char *raw)
{
    List *result = NIL;
    char *str = pstrdup(raw);  /* Make a copy of the string because strtok modifies it */
    char *tok = strtok(str, " ");
    while (tok)
    {
        result = lappend(result, pstrdup(tok));
        tok = strtok(NULL, " ");
    }
    return result;
}

/*
 * String comparison function for list sorting.
 */
static int
list_string_cmp(const ListCell *a, const ListCell *b)
{
    const char *sa = (const char *) lfirst(a);
    const char *sb = (const char *) lfirst(b);
    return strcmp(sa, sb);
}

/*
 * Checks whether all required scopes are present in the granted scopes.
 * Lists are sorted beforehand for easier comparison.
 *
 * Returns true if all required scopes are found in granted scopes.
 */
bool
check_scopes(List *granted, List *required)
{
    ListCell *gcell;
    ListCell *rcell;

    /* Sort both lists to simplify comparison */
    list_sort(granted, list_string_cmp);
    list_sort(required, list_string_cmp);

    gcell = list_head(granted);
    rcell = list_head(required);

    while (rcell != NULL && gcell != NULL)
    {
        char *r = (char *) lfirst(rcell);
        char *g = (char *) lfirst(gcell);
        int cmp = strcmp(r, g);

        if (cmp == 0)
        {
            /* Match found — move to the next required element */
            rcell = lnext(required, rcell);
            gcell = lnext(granted, gcell);
        }
        else if (cmp > 0)
        {
            /* granted is behind — move to the next granted element */
            gcell = lnext(granted, gcell);
        }
        else
        {
            /* required element not found in granted — return false */
            return false;
        }
    }

    /* If not all required elements were found — error */
    if (rcell != NULL)
        return false;

    return true;
}
