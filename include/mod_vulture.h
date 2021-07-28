/**
 * \file     mod_vulture.h
 * \author   Kevin Guillemot, Anthony Dechy
 * \version  1.0
 * \date     05/11/15
 * \license  GPLv3
 * \brief    Headers of the mod_vulture module
 */

#ifndef VULTURE_ENGINE_MOD_VULTURE_H
#define VULTURE_ENGINE_MOD_VULTURE_H


/*************************/
/* Inclusion of .H files */
/*************************/

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdarg.h>

#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"

#include "ap_config.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_base64.h"

#include "hiredis.h"
#include <openssl/sha.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include <openssl/ossl_typ.h>
#include "kerberos_client.h"


/*************/
/* Constants */
/*************/

    /*---------------------------*/
    /* MODULE-part needed macros */
    /*---------------------------*/

extern module AP_MODULE_DECLARE_DATA vulture_module;

#define AP_LOG_WRITE(log_level,r,format,...) { \
    ap_log_rerror(APLOG_MARK,log_level,0,r,format,## __VA_ARGS__); }

#define AP_LOG_TRACE8(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE8, r, format, ## __VA_ARGS__); }   /* trace-level 8 messages */

#define AP_LOG_TRACE7(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE7, r, format, ## __VA_ARGS__); }   /* trace-level 7 messages */

#define AP_LOG_TRACE6(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE6, r, format, ## __VA_ARGS__); }   /* trace-level 6 messages */

#define AP_LOG_TRACE5(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE5, r, format, ## __VA_ARGS__); }   /* trace-level 5 messages */

#define AP_LOG_TRACE4(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE4, r, format, ## __VA_ARGS__); }   /* trace-level 4 messages */

#define AP_LOG_TRACE3(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE3, r, format, ## __VA_ARGS__); }   /* trace-level 3 messages */

#define AP_LOG_TRACE2(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE2, r, format, ## __VA_ARGS__); }   /* trace-level 2 messages */

#define AP_LOG_TRACE1(r, format, ...) { \
    AP_LOG_WRITE(APLOG_TRACE1, r, format, ## __VA_ARGS__); }   /* trace-level 1 messages */

#define AP_LOG_DEBUG(r, format, ...) { \
    AP_LOG_WRITE(APLOG_DEBUG, r, format, ## __VA_ARGS__); }     /* debug-level messages */

#define AP_LOG_INFO(r, format, ...) { \
    AP_LOG_WRITE(APLOG_INFO, r, format, ## __VA_ARGS__); }      /* informational */

#define AP_LOG_NOTICE(r, format, ...) { \
    AP_LOG_WRITE(APLOG_NOTICE, r, format, ## __VA_ARGS__); }    /* normal but significant condition */

#define AP_LOG_WARNING(r, format, ...) { \
    AP_LOG_WRITE(APLOG_WARNING, r, format, ## __VA_ARGS__); }   /* warning conditions */

#define AP_LOG_ERROR(r, format, ...) { \
    AP_LOG_WRITE(APLOG_ERR, r, format, ## __VA_ARGS__); }       /* error conditions */

#define AP_LOG_CRIT(r, format, ...) { \
    AP_LOG_WRITE(APLOG_CRIT, r, format, ## __VA_ARGS__); }      /* critical conditions */

#define AP_LOG_ALERT(r, format, ...) { \
    AP_LOG_WRITE(APLOG_ALERT, r, format, ## __VA_ARGS__); }     /* action must be taken immediately */

#define AP_LOG_EMERG(r, format, ...) { \
    AP_LOG_WRITE(APLOG_EMERG, r, format, ## __VA_ARGS__); }     /* system is unusable */


    /*-----------------------------*/
    /* SESSIONS-part needed macros */
    /*-----------------------------*/

/**
 * \def LEN_403
 *      The length of the 403 response body, in bytes
 */
#define LEN_403 246

/**
 * \def HEADER_COOKIE_MAX_SIZE
 *      The maxmimum length of the Cookie field in an HTTP header request
 */
#define HEADER_COOKIE_MAX_SIZE 4096

/**
 * \def NB_MAX_DIGIT_INT
 *      The maximum number of digits in an integer (11 digits max)
 */
#define NB_MAX_DIGIT_INT 11

/**
 * \def BYTES_READ_NOTE
 *      The index of bytes received in r->notes
 */
#define BYTES_READ_NOTE "mod_svm4.bytes_read"

/**
 * \def STRING_SIZE
 *      The size of the string generated during the creation of the token
 */
#define STRING_SIZE 32

/**
 * \def PATH_TO_PORTAL_SIZE
 *      The maximum length of the path to access a vhost portal
 */
#define PATH_TO_PORTAL_SIZE 100

/**
 * \def TOKEN_SIZE
 *      The maximum length of the token (SHA-256 = 64 chars + Null byte)
 */
#define TOKEN_SIZE (2*SHA256_DIGEST_LENGTH+1)

/**
 * \def APPLICATION_URL_MAX_SIZE
 *      The maximum length of a complete Application URL
 */
#define APPLICATION_URL_MAX_SIZE 300

/**
 * \def HEADER_MAX_SIZE
 *      The maximum length of the Header field in an HTTP request to the requested app
 */
#define HEADER_MAX_SIZE 1024

/**
 * \def LOGIN_MAX_SIZE
 *      The maximum length of the login retrieve during authentication
 */
#define LOGIN_MAX_SIZE 32

/**
 * \def CIPHER_KEY_MAX_SIZE
 *      The maximum length of the key for the cipher (256 bits -> 256/8 bytes)
 */
#define CIPHER_KEY_MAX_SIZE (256 / 8)

/**
 * \def CIPHER_IV_SIZE
 *      The maximum length of the key for the cipher (256 bits -> 256/8 bytes)
 */
#define CIPHER_IV_SIZE (256 / 8)


    /*---------------------------*/
    /* CONFIG-part needed macros */
    /*---------------------------*/

/**
 * \def CONTEXT_SIZE
 *      The maximum length of the Apache context (used for per directory configuration)
 */
#define CONTEXT_SIZE 512

/**
 * \def REDIS_IP_SIZE
 *      The maximum length of a the Redis IP (IPv4 or IPv6)
 */
#define REDIS_IP_SIZE 40

/**
 * \def REDIS_PASS_SIZE
 *      The size of the redis password
 */
#define REDIS_PASSWORD_SIZE 65

/**
 * \def URL_SCHEME_MAX_SIZE
 *      The maximum length of the URL scheme (http:// or https://)
 */
#define URL_SCHEME_MAX_SIZE 9

/**
 * \def DISCONNECT_URL_MAX_SIZE
 *      The maximum length of a complete Disconnect URL
 */
#define DISCONNECT_URL_MAX_SIZE 300

/**
 * \def APPLICATION_ID_SIZE
 *      The maximum length of the application id (from mongoDB's id)
 */
#define APPLICATION_ID_SIZE 25

/**
 * \def TOKEN_NAME_MAX_SIZE
 *      The maxmimum length of the token's name 
 */
#define TOKEN_NAME_MAX_SIZE 32

/**
 * \def COOKIE_PATH_MAX_SIZE
 *      The maximum length of the cookie PATH attribute
 */
#define COOKIE_PATH_MAX_SIZE 100


    /*--------------------------*/
    /* REDIS-part needed macros */
    /*--------------------------*/

/**
 * \def REDIS_SOCKET
 *      The path of the redis local socket
 */
#define REDIS_SOCKET "/var/db/redis/redis.sock"

/**
 * \def REDIS_MAX_RETRY
 *      The number max of retries to reconnect to redis
 */
#define REDIS_MAX_RETRY 3

/**
 * \def REDIS_LOCKED
 *      The status of the mutex used to lock redis connection
 */
#define REDIS_LOCKED 1

/**
 * \def REDIS_LOST
 *      The flag to indicate if the redis connection was lost
 */
#define REDIS_LOST -1

/**
 * \def REDIS_LOST
 *      The flag to indicate if the redis connection was lost
 */
#define INBOUND_SCORE_TX "inbound_anomaly_score"


    /*---------------------------*/
    /* FILTER-part needed macros */
    /*---------------------------*/

/**
 * \def VULTURE_OUT_FILTER_NAME
 *      The name of the mod_vulture's output_filter
 */
#define VULTURE_OUT_FILTER_NAME "MOD_VULTURE_OUT"

/**
 * \def VULTURE_COOKIE_ENCRYPTION_OUT_FILTER_NAME
 *      The name of the mod_vulture's cookie encryption dedicated output_filter
 */
#define VULTURE_COOKIE_ENCRYPTION_OUT_FILTER_NAME "COOKIE_ENCRYPTION_OUT"

/**
 * \def NOTICE_SCORE_TX
 *      The name of the tx_var : tx.notice_anomaly_score
 */
#define NOTICE_SCORE_TX "notice_anomaly_score"

/**
 * \def WARNING_SCORE_TX
 *      The flag to indicate if the redis connection was lost
 */
#define WARNING_SCORE_TX "warning_anomaly_score"

/**
 * \def ERROR_SCORE_TX
 *      The flag to indicate if the redis connection was lost
 */
#define ERROR_SCORE_TX "error_anomaly_score"

/**
 * \def CRITICAL_SCORE_TX
 *      The flag to indicate if the redis connection was lost
 */
#define CRITICAL_SCORE_TX "critical_anomaly_score"

/**
 * \def THRESHOLD_SCORE_TX
 *      The flag to indicate if the redis connection was lost
 */
#define THRESHOLD_SCORE_TX "inbound_anomaly_score_threshold"


/*********/
/* Enums */
/*********/

typedef enum {
    NONE = 0,
    RC4 = 1,
    AES_128 = 2,
    AES_256 = 3,
    NBR_CIPHERS
} cipher_t;

/**************/
/* Structures */
/**************/

/**
 * Typedef to make the function pointer tab easier to read
 */
typedef const EVP_CIPHER* (*cipher_func_t)(void);

/**
 * \struct  server_config mod_vulture.h
 *          Regroup all server directives in a structure
 */
typedef struct {
    char redis_ip[REDIS_IP_SIZE];
    int redis_port;
    char redis_password[REDIS_PASSWORD_SIZE];
    char cookie_name[TOKEN_SIZE];
    char portal_cookie_name[TOKEN_SIZE];
    char public_token_name[TOKEN_SIZE];
    char oauth2_token_name[TOKEN_NAME_MAX_SIZE];
    /* Redis needed attributes - connections */
    redisContext *redis_master_conn;
    redisContext *redis_slave_conn;
    apr_thread_mutex_t *redis_lock;
} server_config;

/**
 * \struct proxy_config mod_vulture.h
 *         Regroup all proxy directives in a structure
 */
typedef struct {
    char context[CONTEXT_SIZE];
    char application_id[APPLICATION_ID_SIZE];
    char url_scheme[URL_SCHEME_MAX_SIZE];
    char path_to_portal[PATH_TO_PORTAL_SIZE];

    int authentication_flag;
    int doubleauthentication_flag;
    int kerberos_flag;
    int oauth2_flag;
    int tracking_flag;
    int stock_asked_uri_flag;
    int update_session_timeout_flag;

    int cookie_encryption_flag;
    cipher_t cipher;
    char cipher_key[CIPHER_KEY_MAX_SIZE + 1];
    char cipher_iv[CIPHER_IV_SIZE + 1];
    
    int session_timeout;
    char cookie_path[COOKIE_PATH_MAX_SIZE];
    char application_url[APPLICATION_URL_MAX_SIZE];
    char disconnect_url[DISCONNECT_URL_MAX_SIZE];
    ap_regex_t *disconnect_regex;
} proxy_config;

/***********/
/* Globals */
/***********/

extern const cipher_func_t OPENSSL_CIPHERS[];
extern const char* OPENSSL_CIPHERS_NAME[];

/************************/
/* Functions signatures */
/************************/

    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
    /* Global directives functions */
    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

        /*-----------------------------------*/
        /* Creation and merging of structure */
        /*-----------------------------------*/

/**
 * \brief    Init a server configuration
 * \details  Init a server configuration with default values
 * \param    pool A pointer to the memory allocated for the configuration
 * \param    srv  A pointer to the server configuration
 * \return   A pointer to the new configuration
 */
void *create_srv_conf(apr_pool_t *pool, server_rec * srv);

/**
 * \brief    Merge all directives from httpd.conf
 * \details  Merge all directives from httpd.conf, like general configuration and vhost specific configuration
 *           With conflict management
 * \param    pool A pointer to the memory allocated for the configuration
 * \param    BASE  A pointer to the server configuration
 * \param    ADD  A pointer to the vhost configuration
 * \return   A pointer to the merged configuration
 */
void *merge_srv_conf(apr_pool_t *pool, void *BASE, void *ADD);

        /*--------------------------------*/
        /* Fill structure with directives */
        /*--------------------------------*/

/**
 * \brief    Retrieve "VltRedisIP"
 * \details  Retrieve the Redis IP from a general directive in httpd.conf
 * \param    cmd    A pointer to the list of directives
 * \param    cfg    A pointer to the configuration
 * \param    arg    The argument retrieve from the directive
 * \return   NULL if success, the error message otherwise
 */
const char* get_redis_ip(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltRedisPort"
 * \details  Retrieve the Redis port from a general directive in httpd.conf
 */
const char* get_redis_port(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltRedisPassword"
 * \details  Retrieve the Redis password from a general directive in httpd.conf
 */
const char* get_redis_password(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltCookieName"
 * \details  Retrieve the token name from a general directive in httpd.conf
 */
const char* get_cookie_name(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltPortalCookieName"
 * \details  Retrieve the portal_token name from a general directive in httpd.conf
 */
const char* get_portal_cookie_name(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltPublicTokenName"
 * \details  Retrieve the public token name from a general directive in httpd.conf
 */
const char* get_public_token_name(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltOAuth2TokenName"
 * \details  Retrieve the OAuth2 token name from a general directive in httpd.conf
 */
const char* get_oauth2_token_name(cmd_parms* cmd, void* cfg, const char* arg);


    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
    /* <Directory> & <Location> specific directives functions  */
    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

        /*-----------------------------------*/
        /* Creation and merging of structure */
        /*-----------------------------------*/

/**
 * \brief    Init a proxy configuration
 * \details  Init a proxy configuration with default values
 * \param    pool A pointer to the memory allocated for the configuration
 * \param    srv  A pointer to the server configuration
 * \return   A pointer to the new configuration
 */
void *create_proxy_conf(apr_pool_t *pool, char* context);

/**
 * \brief    Merge 2 proxy configurations
 * \details  Merge 2 proxy configuration directives, like general configuration and vhost specific configuration
 *              with conflict management
 * \param    pool   A pointer to the memory allocated for the configuration
 * \param    BASE   A pointer to the server configuration
 * \param    ADD    A pointer to the vhost configuration
 * \return   A pointer to the merged configuration
 */
void *merge_proxy_conf(apr_pool_t *pool, void *BASE, void *ADD);


        /*--------------------------------*/
        /* Fill structure with directives */
        /*--------------------------------*/

/**
 * \brief    Retrieve "VltApplicationID"
 * \details  Retrieve the application id from a vhost specific directive in httpd.conf
 * \param    cmd    A pointer to the list of directives
 * \param    cfg    A pointer to the configuration
 * \param    arg    The argument retrieve from the directive
 * \return   NULL if success something else otherwise
 */
const char* get_application_id(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltURLScheme"
 * \details  Retrieve the url scheme of the application (http:// or https://)
 */
const char* get_url_scheme(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltPathToPortal"
 * \details  Retrieve the url of the portal (including portal_cookie_name)
 */
const char* get_path_to_portal(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltAuthenticationRequired"
 * \details  Is authentication required on this app
 */
const char* get_authentication_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltDoubleAuthenticationRequired"
 * \details  Is double-authentication required on this app
 */
const char* get_doubleauthentication_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltKerberosActivated"
 * \details  Is kerberos activated on this app
 */
const char* get_kerberos_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltStatelessOAuth2Enable"
 * \details  Is stateless-OAuth2 activated on this app
 */
const char* get_oauth2_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltTrackingRequired"
 * \details  Is anonymous tracking mode enabled on this app
 */
const char* get_tracking_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltStockAskedUri"
 * \details  Is needed to stock asked uri by user in Redis
 */
const char* get_stock_asked_uri_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltUpdateSessionTimeout"
 * \details  Update session timeout on each request
 */
const char* get_update_session_timeout_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief    Retrieve "VltSessionTimeout"
 * \details  Timeout value of the sessions
 */
const char* get_session_timeout(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltCookiePath"
 * \details  The path of the vulture cookie
 */
const char* get_cookie_path(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltAppURL"
 * \details  Application URL
 */
const char* get_application_url(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief    Retrieve "VltDisconnectURL"
 * \details  Regex used to match disconnect url
 */
const char* get_disconnect_url(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief Retrieve "VltCookieEncrypt"
 * \details Is cookie encryption activated on this app
 */
const char* get_cookie_encryption_flag(cmd_parms* cmd, void* cfg, int flag);

/**
 * \brief Retrieve "VltCookieCipher"
 * \details Get the type of encryption to use for the cookies
 */
const char* get_cookie_cipher(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief Retrieve "VltCookieCipherKey"
 * \details Get the key to use for cookie encryption
 */
const char* get_cookie_cipher_key(cmd_parms* cmd, void* cfg, const char* arg);

/**
 * \brief Retrieve "VltCookieCipherIV"
 * \details Get the initialisation vector to use during cookie encryption
 */
const char* get_cookie_cipher_iv(cmd_parms* cmd, void* cfg, const char* arg);


    /*-*-*-*-*-*-*-*-*-*-*/
    /* Module functions  */
    /*-*-*-*-*-*-*-*-*-*-*/

        /*-------------------------------*/
        /* mod_vulture_filters functions */
        /*-------------------------------*/

/**
* \brief    Handle The hooked request
* \details  Handle The request
* \param    f      The filter
* \return   bb     The bucket brigade
*/
apr_status_t vulture_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);


        /*-------------------------------*/
        /* mod_vulture_handler functions */
        /*-------------------------------*/

/**
 * \brief    Handle The hooked request
 * \details  Handle The request
 * \param    r      The request
 * \return   int    An HTTP code
 */
int vulture_handler(request_rec *r);


        /*-----------------------------*/
        /* mod_vulture_redis functions */
        /*-----------------------------*/

/**
* \brief   Perform Redis query
* \details Perform redis query, try to reconnect if connection is lost
* \param   redis_connection     The redisContext used to contact Redis
* \param   r                    The request
* \param   reply_ptr            A pointer to a redisReply struct
* \param   query_format         The format query to send to Redis
* \param   ...                  The query_format format parameters
* \return  REDIS_LOST if connection is lost, 1 otherwize
*/
int perform_redis_query(redisContext **redis_connection, request_rec *r, redisReply **reply_ptr, const char *query_format, ...);

/**
 * \brief   Connect to the Redis unix socket
 * \details Connect to the Redis unix socket (see macro REDIS_SOCKET)
 * \param   redis_password      The password to authenticate to the Redis server
 * \return  A redisContext connection object, NULL if an error occur during connection
 */
redisContext* connect_to_redis_unix_socket(void);

/**
 * \brief   Connect to the master Redis server
 * \details Connect to the master Redis server if the local Redis server is a slave
 * \param   redis_connection    The connection to the local Redis server
 * \param   redis_password      The password to authenticate to a Redis server
 * \return  A redisContext connection object, NULL if an error occur during connection
 */
redisContext* connect_to_redis_master(request_rec* r, redisContext* redis_connection, char* redis_password);


        /*-------------------------------*/
        /* mod_vulture_session functions */
        /*-------------------------------*/

/**
 * \brief    Get the vulture token in header
 * \details  Get the vulture token in the Cookie header
 * \param    header         A pointer to the header field of the request
 * \param    token_name     The name of the token to look after
 * \return   The token's value, NULL if not present
 */
char* get_application_cookie_from_header(request_rec* r, server_config* config);

/**
 * \brief   Concatenate public_token to path_to portal
 * \details Allocate and return path_to_portal+'/'+public_token
 * \param   public_token    The public token of the app
 * \param   path_to_portal  The complete url of the portal
 * \return  The char* allocated
 */
void int2str(char *dst, int to_convert);

/**
 * \brief   Generate a random token
 * \details Generate a random token 40 bytes long
 * \return  The generated token
 */
char *get_unique_token_in_redis(apr_pool_t *pool); //redisContext* redis_connection);

/**
 * \brief    Add the generated token in the Redis server
 * \details  Add the generated token in the Redis server with all informations needed
 * \param    token              The token value
 * \param    application_id     The application id
 * \param    sessions_timeout   The time a session is valid before expiration
 * \param    redis_connection   The connexion to the redis server
 * \return   1 if the insertion in Redis is OK, 0 otherwise
 */
int add_anonymous_user_in_redis(redisContext* redis_connection, proxy_config* pxy_config, request_rec *r, char* token,
                                 char* url);

/**
 * \brief    Redirect the user to the vhost portal
 * \details  Redirect the user to the vhost portal
 * \param    r                  The user's initial request
 * \param    srv_config         The server config
 * \param    pxy_config         The directory config
 * \param    redis_connection   The redis connection
 * \param    cookie_value       The application cookie
 * \return   An HTTP code (302 or 500 if cannot contact Redis)
 */
int redirect_to_portal(request_rec* r, server_config* srv_config, proxy_config* pxy_config,
                       redisContext* redis_connection, char* cookie_value);

/**
 * \brief    Redirect the user
 * \details  Redirect the user (to different url depending on type)
 * \param    r                  The user's initial request
 * \param    srv_config         The server config
 * \param    pxy_config         The directory config
 * \param    cookie_value       The application cookie
 * \param    type               The type defining to what url redirect
 * \return   An HTTP code to specify a redirection
 */
int redirect_to_module(request_rec* r, server_config* srv_config, proxy_config* pxy_config, char* cookie_value,
                       int type);

/**
 * \brief Revoke token in Redis
 * \details Delete cookie_value entries in Redis (disconnect the user from the app)
 * \param  r                     The user's initial request
 * \param  cookie_value          The application cookie
 * \return redis_connection      The connection to the redis server (master required to delete token)
 */
int revoke_token_in_redis( request_rec* r, char *cookie_value, redisContext* redis_connection );

/**
 * \brief Add headers to request
 * \details Add 'headers' value retrieved from Redis in request to the requested app
 * \param  r                     The user's initial request
 * \param  headers_to_send       The headers retrieved from Redis, in the following format : 'a:b\r\nc:d\r\n...'
 * \return Request_rec object with headers added
 */
request_rec *add_headers_to_send_to_request( request_rec* r, char *headers_to_send );

/**
 * \brief    Get infos in redis with vulture token
 * \details  Get 'login,(double)authenticated,headers,krb5ccname,krb5service' with token from Redis
 * \param    header A pointer to the header field of the request
 * \param    token_name The name of the token to look after
 * \return   The token's value, NULL otherwise
 */
int get_infos_in_redis_with_cookie_value(redisContext *redis_conn, request_rec *r, char *token, redisReply **reply);

        /*-----------------------------------------*/
        /* mod_vulture_cookie_encryption functions */
        /*-----------------------------------------*/

/**
 * \brief Decide to do the cookie encryption or not and pass to the next filter.
 * \param f Apache filter structure to work on.
 * \param in Apache brigade to work with.
 * \return Status of passing the next filter in the stack.
 */
apr_status_t vulture_cookie_encryption_output_filter(ap_filter_t* f,
						     apr_bucket_brigade* in);

/**
 * \brief Decide to do the cookie decryption or not.
 * \param r Apache request structure to work on.
 * \return Status
 */
apr_status_t vulture_cookie_encryption_prr_hook(request_rec* r);

#endif //VULTURE_ENGINE_MOD_VULTURE_H
