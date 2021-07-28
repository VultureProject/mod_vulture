/**
 * \file     mod_vulture.c
 * \authors  Anthony Dechy, Kevin Guillemot, Baptiste De Magnieville, Jeremie Jourdin
 * \version  1.0
 * \date     01/03/17
 * \license  GPLv3
 * \brief    Module to manage authentication and access to the resources protected by Vulture
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_vulture.h"


/**
 * List all directives and associate their name with their handler
 */
static const command_rec vulture_directives[] = {
        AP_INIT_TAKE1("VltRedisIP", get_redis_ip, NULL, RSRC_CONF, "The IPv4 or IPv6 address of Redis"),
        AP_INIT_TAKE1("VltRedisPort", get_redis_port, NULL, RSRC_CONF, "The port where Redis listen"),
        AP_INIT_TAKE1("VltRedisPassword", get_redis_password, NULL, RSRC_CONF, "The password needed to connect to a Redis server"),
        AP_INIT_TAKE1("VltCookieName", get_cookie_name, NULL, RSRC_CONF, "The name of the cookie used for authentication"),
        AP_INIT_TAKE1("VltPortalCookieName", get_portal_cookie_name, NULL, RSRC_CONF, "The name of the portal_cookie used for authentication"),
        AP_INIT_TAKE1("VltPublicTokenName", get_public_token_name, NULL, RSRC_CONF, "The name of the token between the module and the portal"),
        AP_INIT_TAKE1("VltOAuth2TokenName", get_oauth2_token_name, NULL, RSRC_CONF, "The name of the stateless oauth2 token"),

        AP_INIT_TAKE1("VltApplicationID", get_application_id, NULL, ACCESS_CONF, "The unique ID of the application given by mongoDB"),
        AP_INIT_TAKE1("VltURLScheme", get_url_scheme, NULL, ACCESS_CONF, "The protocol http or https to access the resource during authentication"),
        AP_INIT_TAKE1("VltPathToPortal", get_path_to_portal, NULL, ACCESS_CONF, "The path to the portal"),

        AP_INIT_FLAG("VltAuthenticationRequired", get_authentication_flag, NULL, ACCESS_CONF, "A flag to required an authentication or not to access ressource"),
        AP_INIT_FLAG("VltDoubleAuthenticationRequired", get_doubleauthentication_flag, NULL, ACCESS_CONF, "A flag to required a double authentication or not to access ressource"),
        AP_INIT_FLAG("VltKerberosActivated", get_kerberos_flag, NULL, ACCESS_CONF, "A flag to indicate if the kerberos authentication is activated"),
        AP_INIT_FLAG("VltStatelessOAuth2Enable", get_oauth2_flag, NULL, ACCESS_CONF, "A flag to indicate if the Oauth2 Stateless authentication is activated"),
        AP_INIT_FLAG("VltTrackingRequired", get_tracking_flag, NULL, ACCESS_CONF, "A flag to enable anonymous tracking mode"),
        AP_INIT_FLAG("VltStockAskedUri", get_stock_asked_uri_flag, NULL, ACCESS_CONF, "A flag to indicate if the asked uri must be stocked in Redis"),
        AP_INIT_FLAG("VltUpdateSessionTimeout", get_update_session_timeout_flag, NULL, ACCESS_CONF, "A flag to indicate if the session tiemout must be updated after each access to the resource"),

	AP_INIT_FLAG("VltCookieEncryption", get_cookie_encryption_flag, NULL, ACCESS_CONF, "A flag to indicate if the cookies sent to the client must be encrypted"),
        AP_INIT_TAKE1("VltCookieCipher", get_cookie_cipher, NULL, ACCESS_CONF, "The cipher to use to encrypt the cookies"),
        AP_INIT_TAKE1("VltCookieCipherKey", get_cookie_cipher_key, NULL, ACCESS_CONF, "The key to use for cookie encryption"),
        AP_INIT_TAKE1("VltCookieCipherIV", get_cookie_cipher_iv, NULL, ACCESS_CONF, "The IV to use for cookie encryption"),

	AP_INIT_TAKE1("VltSessionTimeout", get_session_timeout, NULL, ACCESS_CONF, "The time a session is valid in Redis"),
        AP_INIT_TAKE1("VltCookiePath", get_cookie_path, NULL, ACCESS_CONF, "The PATH attribute to insert in the mod_vulture's cookie for authentication"),
        AP_INIT_TAKE1("VltAppURL", get_application_url, NULL, ACCESS_CONF, "The complete URL path to access the application"),
        AP_INIT_TAKE1("VltDisconnectURL", get_disconnect_url, NULL, ACCESS_CONF, "Absolute URL for disconnect the user - Revoke his token"),
        AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};


// FIXME: NEED TO FIND A WAY TO SHARE REDIS CONNEXION BETWEEN HANDLER => DONE
// TODO : Only make a ("HMGET %s",cookie) and retrieve the needed attributes "au fur et a mesure" => DONE
// TODO : Don't do redirection to set the token (302+Set-Cookie) But "return OK" and add "Set-Cookie" to headers-out
// TODO NEXT :   WARNING : ONLY IF NOT PORTAL BUT TRACKING !! IF PORTAL -> SSO NEED REDIRECTION !

//static int vulture_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server_base) {
//    /* Check if we are already passed here */
//    apr_file_t *out = NULL;
//
//    apr_file_open_stderr(&out, pconf);
//
//    apr_file_printf(out, "Example module configuration test routine\n");
//
//    void *init_flag = NULL;
//    apr_pool_userdata_get(&init_flag, "modvulture-init-flag", server_base->process->pool);
//    if (init_flag == NULL) { // first load
//        apr_pool_userdata_set((const void *)1, "modvulture-init-flag", apr_pool_cleanup_null,
//                              server_base->process->pool);
//    } else {
//        server_rec *s = NULL;
//        server_config *conf = NULL;
//        for( s = server_base ; s ; s = s->next ) {
//            conf = ap_get_module_config(s->module_config, &vulture_module);
//            if( conf->redis_slave_conn == NULL) {
//                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, "Mod_vulture::post_config: Cannot connect to slave REDIS, "
//                                     "verify if it is correctly up");
//
//                //return !OK;
//            } else if( conf->redis_master_conn == NULL) {
//                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, "Mod_vulture::post_config: Cannot connect to slave REDIS, "
//                                     "verify if it is correctly up");
//                //return !OK;
//            }
//        }
//    }
//    return OK;
//}

/**
 *  Initialize one Redis slave & one master connections by child
 *   There can be only one if slave=master (socket unix connection has ROLE=master)
 */
static apr_status_t vulture_pool_cleanup(void *parm) {
    server_config *conf = (server_config*) parm;

    if( !conf )
        return APR_SUCCESS;

    /* Lock the mutex */
    if( conf->redis_lock )
        apr_thread_mutex_lock(conf->redis_lock);
    /* Free redis master connection */
    if( conf->redis_master_conn ) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Closing master REDIS connection");
        redisFree(conf->redis_master_conn);
        if (conf->redis_slave_conn == conf->redis_master_conn)
	    conf->redis_slave_conn = NULL;
        conf->redis_master_conn = NULL;
    }
    /* Free redis slave connection (already freed if slave_conn=master_conn) */
    if( conf->redis_slave_conn ) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Closing slave REDIS connection");
        redisFree(conf->redis_slave_conn);
        conf->redis_slave_conn = NULL;
    }
    /* Unlock mutex */
    if( conf->redis_lock )
        apr_thread_mutex_unlock(conf->redis_lock);

    return APR_SUCCESS;
}

/**
 *  Initialize one Redis slave & one master connections by child
 *   There can be only one if slave=master (socket unix connection has ROLE=master)
 */
static void vulture_child_init(apr_pool_t *p, server_rec *server_base) {

    /* Connect to redis by unix socket (REDIS_SOCKET) */
    redisContext *redis_slave_conn = connect_to_redis_unix_socket();
    if( redis_slave_conn->err != REDIS_OK ) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, NULL, "Mod_vulture::child_init: Cannot connect to slave REDIS, "
                                                         "verify if it is correctly up");
    }
    /* Connect to redis master : slave_conn is ROLE=MASTER, else connect by TCP */
    redisContext *redis_master_conn = connect_to_redis_master(NULL, redis_slave_conn, NULL);
    if( redis_master_conn->err != REDIS_OK ) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, NULL, "Mod_vulture::child_init: Cannot connect to master REDIS, "
                                                         "verify if it is correctly up");
    }
    /* Copy the initiate connection for each server_rec configuration */
    server_rec *s = NULL;
    server_config *conf = NULL;
    for( s=server_base ; s ; s=s->next ) {
        conf = ap_get_module_config(s->module_config, &vulture_module);
        conf->redis_slave_conn = redis_slave_conn;
        conf->redis_master_conn = redis_master_conn;
    }
    /* Register cleanup that will be performed when pool childs will be destroyed */
    apr_pool_cleanup_register(p, conf, vulture_pool_cleanup, apr_pool_cleanup_null);
}



static void insert_filters(request_rec *r) {
    ap_add_output_filter(VULTURE_OUT_FILTER_NAME, NULL, r, r->connection);
    ap_add_output_filter(VULTURE_COOKIE_ENCRYPTION_OUT_FILTER_NAME,
			 NULL, r, r->connection);
}

/**
 *  Integration of the module in the request management process
 *  Actually placed in the fixups stage due to SSL dependency
 */
static void register_hooks(apr_pool_t *poll) {

    /* Initialize Redis connections */
    ap_hook_child_init(vulture_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    /* Verify redis connections */
    //ap_hook_post_config(vulture_post_config,NULL,NULL,APR_HOOK_REALLY_LAST);

    static const char *const asz_pre[] = { "mod_setenvif.c", "mod_rewrite.c", NULL };

    /* make sure mod_vulture occurs AFTER mod_rewrite's logic */
    ap_hook_header_parser(vulture_cookie_encryption_prr_hook, NULL, asz_pre, APR_HOOK_FIRST);
    ap_hook_header_parser(vulture_handler, asz_pre, NULL, APR_HOOK_FIRST);

    ap_hook_insert_filter(insert_filters, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter(VULTURE_OUT_FILTER_NAME, vulture_output_filter,
			      NULL, AP_FTYPE_RESOURCE);
    ap_register_output_filter(VULTURE_COOKIE_ENCRYPTION_OUT_FILTER_NAME,
			      vulture_cookie_encryption_output_filter, NULL,
			      AP_FTYPE_CONTENT_SET);

}

/**
 * Define the functions used to retrieve all the server and directory directives and for merging them
 */
module AP_MODULE_DECLARE_DATA vulture_module;
AP_DECLARE_MODULE(vulture) = {
        STANDARD20_MODULE_STUFF,
        create_proxy_conf,
        merge_proxy_conf,
        create_srv_conf,
        merge_srv_conf,
        vulture_directives,
        register_hooks
};
