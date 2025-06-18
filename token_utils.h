#ifndef TOKEN_UTILS_H
#define TOKEN_UTILS_H

#include <stdbool.h>

#include "common/jsonapi.h"
#include "nodes/pg_list.h"

const char* parse_token_payload(const char *token);
void extract_sub_scope_fields(const char *json, char **sub_field, char **scope_field);
const char *decode_base64(const char *b64);
char *base64url_to_base64(const char *b64url);
List *split_scopes(const char *raw);
bool check_scopes(List *granted, List *required);

#endif
