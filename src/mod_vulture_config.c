/**
 * \file     mod_vulture_config.c
 * \authors  Kevin Guillemot, Anthony Dechy, Jeremie Jourdin
 * \version  1.0
 * \date     01/03/17
 * \license  GPLv3
 * \brief    Include file to handle Apache httpds configuration directives
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include <mod_vulture.h>
#include "mod_vulture.h"


/********************/
/* Global variables */
/********************/

static int threaded_mpm = 0;


/***************************/
/* Definition of functions */
/***************************/

    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
    /* Global directives functions */
    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

        /*-----------------------------------*/
        /* Creation and merging of structure */
        /*-----------------------------------*/

/**
 *  Define the server configuration (at the top level of the configuration file)
 */
void *create_srv_conf(apr_pool_t *pool, server_rec *s) {

    server_config *srv_cfg = apr_pcalloc(pool, sizeof(server_config));

    // Set default values of the configuration if enought memory is allocated
    if(srv_cfg) {
        strncpy(srv_cfg->redis_ip, "127.0.0.1", REDIS_IP_SIZE);
        srv_cfg->redis_port = 6379;
        strncpy(srv_cfg->redis_password, "redis_password", REDIS_PASSWORD_SIZE);
        strncpy(srv_cfg->cookie_name, "vulture_app", TOKEN_NAME_MAX_SIZE);
        strncpy(srv_cfg->portal_cookie_name, "vulture_portal", TOKEN_NAME_MAX_SIZE);
        strncpy(srv_cfg->public_token_name, "token_data", TOKEN_SIZE);
        strncpy(srv_cfg->oauth2_token_name, "X-Vlt-Token", TOKEN_NAME_MAX_SIZE);

        ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
        if( threaded_mpm )
            apr_thread_mutex_create(&srv_cfg->redis_lock, APR_THREAD_MUTEX_DEFAULT, pool);
    }

    return srv_cfg;
}

/**
 *  Merge the server's configuration with all the other directives to result in one final configuration file
 */
void *merge_srv_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    server_config *base = (server_config *) BASE ;
    //server_config *add = (server_config *) ADD ;
    server_config *conf = (server_config *) apr_pcalloc(pool, sizeof(server_config));

    // Merge directives if enought memory is allocated
    if (conf) {
        strncpy(conf->redis_ip, base->redis_ip, REDIS_IP_SIZE);
        conf->redis_port = base->redis_port;
        strncpy(conf->redis_password, base->redis_password, REDIS_PASSWORD_SIZE);
        strncpy(conf->cookie_name, base->cookie_name, TOKEN_NAME_MAX_SIZE);
        strncpy(conf->portal_cookie_name, base->portal_cookie_name, TOKEN_NAME_MAX_SIZE);
        strncpy(conf->public_token_name, base->public_token_name, TOKEN_SIZE);
        strncpy(conf->oauth2_token_name, base->oauth2_token_name, TOKEN_NAME_MAX_SIZE);

        if( !conf->redis_lock )
            conf->redis_lock = base->redis_lock;
    }

    return conf ;
}


        /*--------------------------------*/
        /* Fill structure with directives */
        /*--------------------------------*/

/**
 *  Retrieve the Redis IP value from the directive
 */
const char* get_redis_ip(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->redis_ip, arg, REDIS_IP_SIZE);
    return NULL;
}

/**
 *  Retrieve the Redis port value from the directive
 */
const char* get_redis_port(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        conf->redis_port = atoi(arg);
    return NULL;
}

/**
 *  Retrieve the Redis password from the directive (not used for the moment because useless)
 */
const char* get_redis_password(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->redis_password, arg, REDIS_PASSWORD_SIZE);
    return NULL;
}

/**
 *  Retrieve the cookie name value from the directive
 */
const char* get_cookie_name(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->cookie_name, arg, TOKEN_NAME_MAX_SIZE);
    return NULL;
}

/**
 *  Retrieve the portal_cookie name value from the directive
 */
const char* get_portal_cookie_name(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->portal_cookie_name, arg, TOKEN_NAME_MAX_SIZE);
    return NULL;
}

/**
 *  Retrieve the token name value from the directive
 */
const char* get_public_token_name(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->public_token_name, arg, TOKEN_SIZE);
    return NULL;
}

/**
 *  Retrieve the OAuth2 token name value from the directive
 */
const char* get_oauth2_token_name(cmd_parms* cmd, void* cfg, const char* arg) {
    server_config *conf = (server_config *) ap_get_module_config(cmd->server->module_config, &vulture_module);
    if (conf)
        strncpy(conf->oauth2_token_name, arg, TOKEN_NAME_MAX_SIZE);
    return NULL;
}


    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
    /* <Directory> & <Location> specific directives functions  */
    /*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

        /*-----------------------------------*/
        /* Creation and merging of structure */
        /*-----------------------------------*/

/**
 *  Define the application configuration (in directory / location sections)
 */
void *create_proxy_conf(apr_pool_t *pool, char* context) {
    context = context ? context : "Newly created configuration";
    proxy_config *proxy_cfg = apr_pcalloc(pool, sizeof(proxy_config));

    if (proxy_cfg) {
        strncpy(proxy_cfg->context, context, CONTEXT_SIZE);
        strncpy(proxy_cfg->application_id, "1234567890abcdefg", APPLICATION_ID_SIZE);
        strncpy(proxy_cfg->url_scheme, "http://", URL_SCHEME_MAX_SIZE);
        strncpy(proxy_cfg->cookie_path, "/", COOKIE_PATH_MAX_SIZE);

        proxy_cfg->authentication_flag = 0;
        proxy_cfg->doubleauthentication_flag = 0;
        proxy_cfg->kerberos_flag = 0;
        proxy_cfg->oauth2_flag = 0;
        proxy_cfg->tracking_flag = 0;
        proxy_cfg->stock_asked_uri_flag = 0;
        proxy_cfg->update_session_timeout_flag = 0;

	proxy_cfg->cookie_encryption_flag = 0;
	proxy_cfg->cipher = NONE;
	memset(proxy_cfg->cipher_key, 0, CIPHER_KEY_MAX_SIZE + 1);
	memset(proxy_cfg->cipher_iv, 0, CIPHER_IV_SIZE + 1);

        proxy_cfg->session_timeout = 300;
        strncpy(proxy_cfg->application_url, "http://example.com", APPLICATION_URL_MAX_SIZE);
        strncpy(proxy_cfg->disconnect_url, "/disconnect", DISCONNECT_URL_MAX_SIZE);
        proxy_cfg->disconnect_regex = ap_pregcomp(pool, proxy_cfg->disconnect_url, AP_REG_NEWLINE); /* Don't match newline against '.' */
        ap_assert(proxy_cfg->disconnect_regex != NULL );
    }
    return proxy_cfg;
}

/**
 *  Merge application's configuration to the others which result in one configuration file without conflict
 */
void *merge_proxy_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    proxy_config *base = (proxy_config *) BASE ;
    proxy_config *add = (proxy_config *) ADD ;
    proxy_config *conf = (proxy_config *) create_proxy_conf(pool, "Merged configuration");

    // Merge directives 
    strncpy(conf->path_to_portal, add->path_to_portal, PATH_TO_PORTAL_SIZE);
    strncpy(conf->application_id, add->application_id, APPLICATION_ID_SIZE);
    strncpy(conf->url_scheme, add->url_scheme, URL_SCHEME_MAX_SIZE);
    strncpy(conf->cookie_path, add->cookie_path, COOKIE_PATH_MAX_SIZE);

    conf->authentication_flag = add->authentication_flag;
    conf->doubleauthentication_flag = add->doubleauthentication_flag;
    conf->kerberos_flag = add->kerberos_flag;
    conf->oauth2_flag = add->oauth2_flag;
    conf->tracking_flag = add->tracking_flag;
    conf->stock_asked_uri_flag = add->stock_asked_uri_flag;
    conf->update_session_timeout_flag = add->update_session_timeout_flag;

    conf->cookie_encryption_flag = add->cookie_encryption_flag;
    conf->cipher = add->cipher;
    strncpy(conf->cipher_key, add->cipher_key, CIPHER_KEY_MAX_SIZE);
    strncpy(conf->cipher_iv, add->cipher_iv, CIPHER_IV_SIZE);

    conf->session_timeout = add->session_timeout;
    strncpy(conf->application_url, add->application_url, APPLICATION_URL_MAX_SIZE);
    strncpy(conf->disconnect_url, add->disconnect_url, DISCONNECT_URL_MAX_SIZE);
    conf->disconnect_regex = ap_pregcomp(pool, conf->disconnect_url, AP_REG_NEWLINE); /* Don't match newline against '.' */
    ap_assert( conf->disconnect_regex != NULL );

    return conf ;
}


        /*--------------------------------*/
        /* Fill structure with directives */
        /*--------------------------------*/

/**
 *  Retrieve the application id value from the directive
 */
const char* get_application_id(cmd_parms* cmd, void* cfg, const char* arg){
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->application_id, arg, APPLICATION_ID_SIZE);
    }

    return NULL;
}

/**
 *  Retrieve the protocol's directive used to access the resource during authentication (http:// or https://)
 */
const char* get_url_scheme(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->url_scheme, arg, URL_SCHEME_MAX_SIZE);
    }

    return NULL;
}

/**
 *  Retrieve the URL to the portal from the directive
 */
const char* get_path_to_portal(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->path_to_portal, arg, PATH_TO_PORTAL_SIZE);
    }
    return NULL;
}

/**
 *  Retrieve the authentication flag value from the directive
 */
const char* get_authentication_flag(cmd_parms* cmd, void* cfg, int flag){
    proxy_config *conf = (proxy_config *) cfg;

    if (conf)
        conf->authentication_flag = flag;

    return NULL;
}

/**
 *  Retrieve the authentication flag value from the directive
 */
const char* get_doubleauthentication_flag(cmd_parms* cmd, void* cfg, int flag){
    proxy_config *conf = (proxy_config *) cfg;

    if(conf)
        conf->doubleauthentication_flag = flag;

    return NULL;
}

/**
 *  Retrieve the kerberos flag value from the directive
 */
const char* get_kerberos_flag (cmd_parms* cmd, void* cfg, int flag) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf)
        conf->kerberos_flag = flag;

    return NULL;
}

/**
 *  Retrieve the oauth2 flag value from the directive
 */
const char* get_oauth2_flag (cmd_parms* cmd, void* cfg, int flag) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf)
        conf->oauth2_flag = flag;

    return NULL;
}

/**
 *  Retrieve the tracking flag value from the directive
 */
const char* get_tracking_flag(cmd_parms* cmd, void* cfg, int flag){
    proxy_config *conf = (proxy_config *) cfg;

    if (conf)
            conf->tracking_flag = flag;

    return NULL;
}

/**
 *  Retrieve the stock_asked_uri directive param
 */
const char* get_stock_asked_uri_flag (cmd_parms* cmd, void* cfg, int flag){
    proxy_config *conf = (proxy_config *) cfg;

    if(conf)
        conf->stock_asked_uri_flag = flag;

    return NULL;
}

/**
 *  Retrieve the update session flag value from the directive
 */
const char* get_update_session_timeout_flag (cmd_parms* cmd, void* cfg, int flag){
    proxy_config *conf = (proxy_config *) cfg;

    if (conf)
        conf->update_session_timeout_flag = flag;

    return NULL;
}

/**
 *  Retrieve the session timeout value from the directive
 */
const char* get_session_timeout(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        conf->session_timeout = atoi(arg);
    }
    return NULL;
}

/**
 *  Retrieve the cookie PATH attribute to create during authentication
 */
const char* get_cookie_path(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->cookie_path, arg, COOKIE_PATH_MAX_SIZE);
    }

    return NULL;
}

/**
 *  Retrieve the application url value from the directive
 */
const char* get_application_url(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->application_url, arg, APPLICATION_URL_MAX_SIZE);
    }

    return NULL;
}

/**
 *  Retrieve the disconnect url value from the directive
 */
const char* get_disconnect_url(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config *) cfg;

    if (conf) {
        strncpy(conf->disconnect_url, arg, DISCONNECT_URL_MAX_SIZE);
    }

    return NULL;
}

/**
 * Retrieve the flag associated to the cookie encryption
 */
const char* get_cookie_encryption_flag(cmd_parms* cmd, void* cfg,
				       int flag) {
    proxy_config *conf = (proxy_config*) cfg;

    if (conf) {
	conf->cookie_encryption_flag = flag;
    }
    return NULL;
}

const char* get_cookie_cipher(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config*) cfg;

    if (conf) {
	for (cipher_t c = NONE; c < NBR_CIPHERS; ++c) {
	    if (!strncmp(arg, OPENSSL_CIPHERS_NAME[c], strlen(OPENSSL_CIPHERS_NAME[c]) + 1)) {
		conf->cipher = c;
		return NULL;
	    }
	}
    }
    return NULL;
}

const char* get_cookie_cipher_key(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config*) cfg;

    if (conf) {
	strncpy(conf->cipher_key, arg, CIPHER_KEY_MAX_SIZE);
    }
    return NULL;
}

const char* get_cookie_cipher_iv(cmd_parms* cmd, void* cfg, const char* arg) {
    proxy_config *conf = (proxy_config*) cfg;

    if (conf) {
	strncpy(conf->cipher_iv, arg, CIPHER_IV_SIZE);
    }
    return NULL;
}
