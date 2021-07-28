/**
 * \file     mod_vulture_session.c
 * \authors  Anthony Dechy, Kevin Guillemot, Jeremie Jourdin
 * \version  1.0
 * \date     28/02/17
 * \license  GPLv3
 * \brief    Token and session helper
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include <mod_vulture.h>
#include "mod_vulture.h"


/*****************************************/
/* Prototypes of internal file fonctions */
/*****************************************/

/**
 * \brief    Extract the token in header
 * \details  Extract the token in header, no matter if other cookies are present
 * \param    header A pointer to the header field of the request
 * \param    token_name The name of the token to look after
 * \return   The token's value, NULL otherwise
 */
static char *extract_vulture_token_from_cookies(apr_pool_t *pool, char* header, char* token_name, char *portal_cookie,
                                                request_rec *r);

/**
 * \brief   Remove all spaces in a string
 * \details Remove all spaces in a string to avoid bad comparison between 2 strings
 * \param   source The string to remove spaces
 * \return  void
 */
static void remove_spaces(char* source);

/**
 * \brief    Set headers length read in notes
 * \details  Set headers length read in request_rec->notes with BYTES_READ_NOTE index
 * \param    r                 The request
 * \param    headers_length    The headers_length to set in notes
 * \return   void
 */
static void set_headers_length_in_notes(request_rec *r, int headers_length);

/**
 * \brief   Concatenate public_token to path_to portal
 * \details Allocate and return path_to_portal+'/'+public_token
 * \param   public_token    The public token of the app
 * \param   path_to_portal  The complete url of the portal
 * \return  The char* allocated
 */
static int get_nb_digits(int number);

/**
 * \brief   Generate a token
 * \details Generate a token according to the CSRF token source code in Django
 * \return  A token value
 */
static char *generate_token(apr_pool_t *pool);

/**
 * \brief   Generate a random string
 * \details Generate a random string according to the CSRF token source code in Django
 * \return  A random string
 */
static void *generate_random_string(unsigned char *random_string);

/**
 * \brief   Concatenate public_token to path_to portal
 * \details Allocate and return path_to_portal+'/'+public_token
 * \param   public_token    The public token of the app
 * \param   path_to_portal  The complete url of the portal
 * \return  The char* allocated
 */
static void hex_to_str(int to_convert, char *result);

/**
 * \brief   Generate the module cookie
 * \details Generate the module cookie which contains the token and the path
 * \param   cookie_name         The Cookie name
 * \param   token_value         The value of the token generated
 * \param   cookie_path         The PATH to access the application
 * \return  The final cookie string (cookie_name=value;path=/path)
 */
static void create_cookie(server_config* srv_config, proxy_config* pxy_config, char *header, char* token_value);

/**
 * \brief   Generate an unique public token
 * \details Generate an unique public token and add it in Redis with the associate private token
 * \param   redis_connection    The connection to the Redis server
 * \param   private_token       The private token generate for authentication
 * \param   session_tiemout    The time in seconds for a user to access resource after authentication
 * \return  The public token inserted in Redis and necesseray for redirection to portal
 */
static char* generate_unique_token_to_insert_in_redis(redisContext* redis_connection, request_rec *r,
                                                      char* private_token);
/**
 * \brief   Concatenate public_token to path_to portal
 * \details Allocate and return path_to_portal+'/'+public_token
 * \param   public_token    The public token of the app
 * \param   path_to_portal  The complete url of the portal
 * \return  The char* allocated
 */
static void get_complete_path_to_portal(char *path_to_portal_with_token, char *public_token, char *path_to_portal);


/***************************/
/* Definition of fonctions */
/***************************/

/**
 *  Extract the cookie header field given in the request to check if the vulture token is present
 */
char* get_application_cookie_from_header(request_rec* r, server_config* config)  {
    // Retrieve each fields in the header's request in an array
    const apr_array_header_t* fields = apr_table_elts(r->headers_in);
    apr_table_entry_t* entry = (apr_table_entry_t *) fields->elts;

    char* cookie_header = NULL;
    char* vulture_token = NULL;
    int headers_length = 0;

    // Loop which iterate thought each fields
    for(int i = 0; i < fields->nelts; i++) {
        headers_length += (strlen(entry[i].key) + strlen(entry[i].val) + 4);
        AP_LOG_DEBUG(r, "Header given %d %s:%s", i + 1, entry[i].key, entry[i].val);
        // Check if the Cookie field exists in the table and set it's content in a pointer
        if (strncasecmp(entry[i].key, "Cookie\0", 7) == 0) {
            cookie_header = strndup(entry[i].val, HEADER_COOKIE_MAX_SIZE);
            vulture_token = extract_vulture_token_from_cookies(r->pool, cookie_header, config->cookie_name,
                                                               config->portal_cookie_name, r);
        }
    }
    // SVM add -> add headers_length in notes to retrieve it in other modules
    headers_length += strlen(r->the_request)+4;
    AP_LOG_TRACE1(r, "Mod_vulture:: Headers length: %d", headers_length);
    set_headers_length_in_notes(r, headers_length);

    return vulture_token;
}

/**
 *  Extract only the token in a liste of cookie from the cookie header field
 */
static char* extract_vulture_token_from_cookies(apr_pool_t *pool, char* cookie_header, char* token_name,
                                                char *portal_cookie, request_rec *r)  {
    char* token = NULL;

    // Remove all spaces in the Cookie header
    remove_spaces(cookie_header);

    size_t cpt=0, cpt2=0;
    size_t len_app_cookie = strlen(token_name);
    size_t len_portal_cookie = strlen(portal_cookie);

    AP_LOG_TRACE1(r, "Mod_vulture::extract_vulture_token: extracting token from cookie '%s'", cookie_header);

    while( *(cookie_header+cpt) != '\0' ) {
        while( *(cookie_header+cpt) == ';' ) {
            cpt++;
        }
        if( !strncmp(cookie_header+cpt, token_name, len_app_cookie) && *(cookie_header+cpt+len_app_cookie) == '=' ) {
            cpt += len_app_cookie+1;
            size_t cpt3 = 0;
            size_t cpt4 = cpt;
            while( *(cookie_header+cpt) != ';' && *(cookie_header+cpt) != '\0' ) {
                cpt++;
                cpt3++;
            }
            if( *(cookie_header+cpt) != '\0' ) {
                cpt++;
            }
            AP_LOG_TRACE2(r, "Mod_vulture::extract_vulture_token: Allocating %lu chars", cpt3+1);
            token = apr_pcalloc( pool, (cpt3+1)*sizeof(char) );
            *stpncpy(token, cookie_header+cpt4, cpt3) = 0x00;
            AP_LOG_TRACE1(r, "Mod_vulture::extract_vulture_token: token_app:'%s'", token);
        }
        else if( (!strncmp(cookie_header+cpt, portal_cookie, len_portal_cookie)
                   && *(cookie_header+cpt+len_portal_cookie) == '=') \
                    || (!strncmp(cookie_header+cpt, "csrftk=", 7)) ) {
            AP_LOG_DEBUG(r, "Mod_vulture::extract_vulture_token: Found csrftk or portal token: removing-it.");
            while( *(cookie_header+cpt) != ';' && *(cookie_header+cpt) != '\0' ) {
                cpt++;
            }
            if( *(cookie_header+cpt) != '\0' ) {
                cpt++;
            }
        }
        else {
            AP_LOG_DEBUG(r, "Mod_vulture::extract_vulture_token: Re-copying token.");
            while( *(cookie_header+cpt) != ';' && *(cookie_header+cpt) != '\0' ) {
                cookie_header[cpt2] = cookie_header[cpt];
                cpt++;
                cpt2++;
            }
            cookie_header[cpt2] = cookie_header[cpt];
            if( *(cookie_header+cpt) != '\0' ) {
                cpt++;
                cpt2++;
            }
        }
    }

    if( cpt2 == 0 ) {
        apr_table_unset(r->headers_in, "Cookie");
        AP_LOG_DEBUG(r, "Mod_vulture::extract_vulture_token: Removing 'Cookie' header empty.");
    } else{
        if( cookie_header[cpt2-1] == ';' ) {
            cookie_header[cpt2-1] = '\0';
        } else {
            cookie_header[cpt2] = '\0';
        }
        apr_table_set (r->headers_in, "Cookie", cookie_header);
        AP_LOG_DEBUG(r, "Mod_vulture::extract_vulture_token: Final token: '%s'", cookie_header);
    }
    return token;
}

/**
 * Remove spaces a string (used to parse cookie header with spaces)
 */
static void remove_spaces(char* source)  {
    char* i = source;
    char* j = source;

    while(*j != 0) {
        *i = *j++;

        if(*i != ' ') {
            i++;
        }
    }
    *i = 0;
}

/**
 *  Set headers_length in r->notes with BYTES_READ_NOTE index
 */
static void set_headers_length_in_notes(request_rec *r, int headers_length) {
    // Transform headers_length in char* and set it in r->notes
    // to retrieve it in other modules
    char str_headers_length[NB_MAX_DIGIT_INT] = {0};
    //snprintf(str_headers_length, NB_MAX_DIGIT_INT, "%d", headers_length);
    int2str(str_headers_length, headers_length);

    apr_table_set(r->notes, BYTES_READ_NOTE, str_headers_length);
}

/**
 *  Get number of digit in int -> (1000 -> 4)
 */
static int get_nb_digits(int number) {
    if( number < 100000 ) {
        if( number < 1000 ) {
            if( number < 10 ) return 1;
            if( number < 100 ) return 2;
            return 3;
        } else {
            if( number < 10000 ) return 4;
            return 5;
        }
    } else {
        if( number < 10000000 ) {
            if( number < 1000000 ) return 6;
            return 7;
        } else {
            if( number < 100000000 ) return 8;
            if( number < 1000000000 ) return 9;
            return 10;
        }
    }
}

/**
 *  Convert int to string ( 900 -> '900' )
 */
void int2str(char *dst, int to_convert) {
    int tmp = to_convert;
    int cpt = get_nb_digits(to_convert)-1;
    do {
        dst[cpt--] = (char)((tmp%10)+48);
    } while( (tmp/=10) > 0 );
}

/**
 *  Generate a unique token according to the existing tokens already in Redis
 */
char *get_unique_token_in_redis(apr_pool_t *pool) { //redisContext* redis_connection) {
    char *token = generate_token(pool);

    // TODO : Verify if token generated already exists in Redis -- NEEDED ?
    // FIXME Segfault with the while loop (reference to NULL)
    //while(redisCommand(redis_connection, "GET %s", token) == NULL) {
    //    free(token);
    //    token = generate_token();
    //}

    return token;
}

/**
 *  Generate a token according to a hashed random string
 */
static char *generate_token(apr_pool_t *pool) {
    // Generate a random string
    unsigned char random_string[STRING_SIZE + 1];
    generate_random_string(random_string);
    unsigned char *unformated_token = SHA256(random_string, STRING_SIZE, NULL);
    char *formated_token = NULL;
    formated_token = apr_palloc(pool, 2 * SHA256_DIGEST_LENGTH + 1);
    char *buffer = formated_token;
    int i;
    char tmp[2] = {0};

    // Format the hash in hexadecimal (example: 10 in decimall will be 0A)
    for( i = 0 ; i < SHA256_DIGEST_LENGTH ; i++ ) {
        hex_to_str((int)unformated_token[i], tmp);
        buffer = stpncpy(buffer, tmp, 2);
    }
    *( buffer ) = '\0';

    buffer = NULL;

    return formated_token;
}

/**
 *  Generate a random string used to generate the vulture token
 */
static void *generate_random_string(unsigned char *random_string) {
    arc4random_buf (random_string, STRING_SIZE-1);
    random_string[STRING_SIZE] = '\0';
    return random_string;
}

/**
 *  Convert byte to double-char ( ex : 0x64 -> '64' )
 */
static void hex_to_str(int to_convert, char *result) {
    int tmp=0;

    tmp = (to_convert>>4)&0xf;
    result[0] = (tmp >= 0xa) ? ((char)(tmp+0x57)) : (char)(tmp+0x30);

    tmp = (to_convert)&0xf;
    result[1] = (tmp >= 0xa) ? ((char)(tmp+0x57)) : (char)(tmp+0x30);
}

/**
 *  Add an anonymous user in redis with a timeout
 */
int add_anonymous_user_in_redis(redisContext* redis_Mconnection, proxy_config* pxy_config, request_rec *r, char* token,
                                char* url) {

    redisReply *reply = NULL;
    if( perform_redis_query(&redis_Mconnection, r, &reply, "HMSET %s login - cn - application_id %s url %s"
            " authenticated 0 doubleauthenticated 0", token, pxy_config->application_id, url) == REDIS_LOST )
        return REDIS_LOST;
    freeReplyObject(reply);

    if( perform_redis_query(&redis_Mconnection, r, &reply, "EXPIRE %s %d", token, pxy_config->session_timeout) == REDIS_LOST )
        return REDIS_LOST;

    freeReplyObject(reply);

    return 0;
}

/**
 *  Respond to the request with the new generated vulture token and redirect to the portal
 */
int redirect_to_portal(request_rec* r, server_config* srv_config, proxy_config* pxy_config,
                       redisContext* redis_Mconnection, char* cookie_value) {

    char* public_token = NULL;
    if( (public_token=generate_unique_token_to_insert_in_redis(redis_Mconnection, r, cookie_value)) == NULL ) {
        AP_LOG_ERROR(r, "Mod_vulture::generate_unique_token: Redis connection LOST");
        return 500;
    }
    // Generate private and public tokens
    char path_to_portal_with_token[PATH_TO_PORTAL_SIZE + 1 + TOKEN_SIZE + 1];
    get_complete_path_to_portal(path_to_portal_with_token, public_token, pxy_config->path_to_portal);
    char cookie_header[TOKEN_SIZE + 1 + TOKEN_NAME_MAX_SIZE + 6 + COOKIE_PATH_MAX_SIZE + 9 + 7 + 1];
    create_cookie(srv_config, pxy_config, cookie_header, cookie_value);

    //Never cache anything here
    apr_table_add(r->headers_out, "Cache-Control", "no-cache, no-store, must-revalidate");
    apr_table_add(r->headers_out, "Pragma", "no-cache");
    apr_table_add(r->headers_out, "Expires", "0");
    // Set the private_token and the path to the portal in the header response
    apr_table_add(r->err_headers_out, "Set-Cookie", cookie_header);
    AP_LOG_DEBUG(r, "Mod_vulture::redirect_to_portal: Set-cookie = '%s'", cookie_header);
    apr_table_add(r->headers_out, "Location", path_to_portal_with_token);
    AP_LOG_DEBUG(r, "Mod_vulture::redirect_to_portal: Redirecting user to '%s'", path_to_portal_with_token);

    return 302;
}

/**
 *  Create the vulture token used for authentication using some security concepts
 */
static void create_cookie(server_config* srv_config, proxy_config* pxy_config, char *header, char* token_value) {
    // Check if the the application's scheme is https to add the secure flag to the cookie
    if (strncmp(pxy_config->url_scheme, "https://", 8) == 0) {
        /* */
        *stpncpy( stpncpy( stpncpy( stpncpy( stpncpy( stpncpy( header, srv_config->cookie_name, TOKEN_NAME_MAX_SIZE ),
                                                      "=", 1),
                                             token_value, TOKEN_SIZE),
                                    ";Path=", 6),
                           pxy_config->cookie_path, COOKIE_PATH_MAX_SIZE),
                  ";httpOnly;secure", 16) = 0x00;
        //snprintf(token, max_size_result, "%s=%s;Path=%s;httpOnly;secure", srv_config->cookie_name, token_value,
        //         pxy_config->cookie_path);
    }
    else {
        /*  ! */
        *stpncpy( stpncpy( stpncpy( stpncpy( stpncpy( stpncpy( header, srv_config->cookie_name, TOKEN_NAME_MAX_SIZE ),
                                                      "=", 1),
                                             token_value, TOKEN_SIZE),
                                    ";Path=", 6),
                           pxy_config->cookie_path, COOKIE_PATH_MAX_SIZE),
                  ";httpOnly", 9) = 0x00;
        //snprintf(token, max_size_result, "%s=%s;Path=%s;httpOnly", srv_config->cookie_name, token_value,
        //         pxy_config->cookie_path);
    }
}

/**
 *  Generate the vulture token with the specified timeout and insert it in Redis
 */
static char* generate_unique_token_to_insert_in_redis(redisContext* redis_connection, request_rec *r,
                                                      char* private_token) {
    char * public_token = get_unique_token_in_redis(r->pool);

    // Add public and private token in Redis
    // Add expiration of the public token in Redis according to the session timeout defined in Apache
    // #FIX 180316 ADY: Set by default the life of the unique token to 5 minutes

    //snprintf(command, TOKEN_SIZE*2+NB_MAX_DIGIT_INT+10, "SETEX %s %d %s", public_token, 300, private_token);
    redisReply *redis_reply = NULL;
    if( perform_redis_query(&redis_connection, r, &redis_reply, "SETEX %s 300 %s", public_token, private_token) == -1 ) {
        return NULL;
    }
    freeReplyObject(redis_reply);

    return public_token;
}

/**
 *  Generate to good path to the portal according with the token in parameter
 */
static void get_complete_path_to_portal(char *path_to_portal_with_token, char *public_token, char *path_to_portal) {
    /* Use stpncpy and not snprintf ! */
    *stpncpy( stpncpy(stpncpy(path_to_portal_with_token, path_to_portal, PATH_TO_PORTAL_SIZE),
                      "/", 1),
              public_token, TOKEN_SIZE) = 0x00;
}

/**
 *  Redirect to the module
 */
int redirect_to_module(request_rec* r, server_config* srv_config, proxy_config* pxy_config, char* cookie_value,
                       int type) {

    char cookie_header[TOKEN_SIZE + 1 + TOKEN_NAME_MAX_SIZE + 6 + COOKIE_PATH_MAX_SIZE + 9 + 7 + 1] = {0};
    create_cookie(srv_config, pxy_config, cookie_header, cookie_value);
    apr_table_add(r->err_headers_out, "Set-Cookie", cookie_header);

    //Never cache anything here
    apr_table_add(r->headers_out, "Cache-Control", "no-cache, no-store, must-revalidate");
    apr_table_add(r->headers_out, "Pragma", "no-cache");
    apr_table_add(r->headers_out, "Expires", "0");

    /* This is a disconnect redirect */
    if (type == 1) {
        char url[APPLICATION_URL_MAX_SIZE+2+TOKEN_SIZE+1+APPLICATION_ID_SIZE+1];
        // snprintf is not efficient
        // stpcpy() returns a pointer to the end of the resultant string, stpncpy is POSIX:2008
        *stpncpy( stpncpy( stpncpy( stpncpy( stpncpy(url, pxy_config->application_url, APPLICATION_URL_MAX_SIZE),
                                             "d_", 2),
                                    srv_config->public_token_name, TOKEN_SIZE),
                           "/", 1),
                  pxy_config->application_id, APPLICATION_ID_SIZE) = 0x00;
        AP_LOG_NOTICE(r, "Mod_vulture::redirect_to_module: Redirecting to deconnection url = '%s'", url);
        apr_table_add(r->headers_out, "Location", url);
    }
    // This is a redirect to asked uri
    else if( type == 2 ) {
        AP_LOG_NOTICE(r, "Mod_vulture:redirect_to_module: Redirecting to asked url = '%s'", r->unparsed_uri);
        apr_table_add(r->headers_out, "Location", r->unparsed_uri);
    }
    /* This is a standard redirect, nothing special */
    else {
        AP_LOG_NOTICE(r, "Mod_vulture:redirect_to_module: Redirecting to default application url = '%s'",
                      pxy_config->application_url);
        apr_table_add(r->headers_out, "Location", pxy_config->application_url);
    }

    return 302;
}

/**
 *  Revoke token in Redis (Delete the 'cookie_value' entries in Redis)
 */
int revoke_token_in_redis( request_rec* r, char *cookie_value, redisContext* redis_Mconnection ) {

    redisReply *reply = NULL;
    int result = 0;
    // Delete token entry in Redis (token = cookie_value)
    if( (result=perform_redis_query(&redis_Mconnection, r, &reply, "DEL %s" ,cookie_value)) == -1 ) {
        AP_LOG_ALERT(r, "Mod_vulture::revoke_token: Redis connection is LOST");
        return REDIS_LOST;
    } else if( reply->integer > 0 ) {
        AP_LOG_DEBUG(r, "Token successfully removed from Redis : %s. %lld entries were deleted.",
                     cookie_value, reply->integer);
    } else {
        AP_LOG_ERROR(r, "Unable to delete the token entry in Redis (%s) : %s.", cookie_value, reply->str);
    }
    freeReplyObject(reply);

    return result;
}


/**
 *  Add 'headers' values retrieved from Redis - if exists - in headers request to the app requested
 */
request_rec *add_headers_to_send_to_request(request_rec* r, char *headers_to_send) {
    char *header_name = headers_to_send;
    char *header_value = NULL;
    size_t two_pts = 0, r_n = 0;

    // headers format = "header_name1:header_value1\r\nheader_name2:header_value2\r\n(...)"
    while( *header_name ) {
        two_pts = strcspn(header_name, ":");
        *(header_name + two_pts) = 0x00;
        header_value = header_name + two_pts + 1;

        r_n = strcspn(header_value, "\r\n");
        *(header_value + r_n) = 0x00;

        // Add header_name:header_value to request headers
        apr_table_add( r->headers_in, header_name, header_value );
        // Don't enable 'Debug' verbosity on production !
        AP_LOG_DEBUG(r, "Adding the following header '%s:%s' to the request towards : %s ", header_name, header_value,
                     r->hostname );

        header_name = header_value + r_n + 2;
    }
    header_name = NULL;
    header_value = NULL;

    return r;
}

/**
 *  Retrieve informations from Redis with given cookie_value
 *  authenticated , headers, login, doubleauthenticated, krb5ccname, krb5service
 *  returns REDIS_LOST or 1
 */
int get_infos_in_redis_with_cookie_value(redisContext *redis_conn, request_rec *r, char *token, redisReply **reply) {

    if( perform_redis_query(&redis_conn, r, reply, "HMGET %s login authenticated doubleauthenticated headers krb5ccname "
            "krb5service", token) == REDIS_LOST ) {
        AP_LOG_ERROR(r, "Mod_vulture::get_infos_in_redis: Redis connection LOST");
        return REDIS_LOST;
    }
    return 1;
}

