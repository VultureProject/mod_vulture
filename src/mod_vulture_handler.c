/**
 * \file     mod_vulture_handler.c
 * \authors  Anthony Dechy, Kevin Guillemot, Jeremie Jourdin
 * \version  1.0
 * \date     28/02/17
 * \license  GPLv3
 * \brief    mod_vulture handler
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_vulture.h"


/***************************/
/* Definition of fonctions */
/***************************/

/**
 *  Implementation of the mod_vulture's logic
 *  Contains all logging commands, directives, datas and sessions management
 */
int vulture_handler(request_rec *r) {

    server_config* srv_config = (server_config *) ap_get_module_config(r->server->module_config , &vulture_module);
    proxy_config* pxy_config = (proxy_config *) ap_get_module_config(r->per_dir_config, &vulture_module);

    if( pxy_config->authentication_flag != 1 && pxy_config->tracking_flag != 1 ) {
        AP_LOG_DEBUG(r, "vulture_handler: DECLINING. Authen flag is '%d', Tracking flag is '%d'",
                     pxy_config->authentication_flag, pxy_config->tracking_flag);
	    return DECLINED;
    }

    AP_LOG_DEBUG(r, "Mod_vulture:: OAuth2 Stateless enabled = %d", pxy_config->oauth2_flag);
    /* If stateless OAuth2 tokens are allowed */
    if( pxy_config->oauth2_flag ) {
        const char *oauth2_token;
        /* Try to retrieve-it from (Cookie) headers */
        if( (oauth2_token=apr_table_get(r->headers_in, srv_config->oauth2_token_name)) != NULL ) {
            AP_LOG_DEBUG(r, "Mod_vulture:: OAuth2 header '%s' successfully retrieven", srv_config->oauth2_token_name);
            /* Look for that token is Redis */
            redisReply *redis_reply = NULL;
            if( perform_redis_query(&srv_config->redis_slave_conn, r, &redis_reply, "HGET oauth2_%s scope", oauth2_token) == REDIS_LOST ) {
                AP_LOG_ERROR(r, "Mod_vulture:: Redis 'HGET oauth2_%s scope' error : Redis connection LOST", oauth2_token);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            /* If the token is found : Continue to another hook (module) */
            if( redis_reply->type == REDIS_REPLY_STRING && redis_reply->len > 0 ) {
                AP_LOG_INFO(r, "Mod_vulture:: OAuth2 stateless token found in header -> user is authenticated");
                return OK;
            } else {
                AP_LOG_DEBUG(r, "Mod_vulture:: OAuth2 stateless token not found in Redis");
            }
            /* If the token is NOT found : Continue the classic scenario */
        } else {
            AP_LOG_DEBUG(r, "Mod_vulture:: Header '%s' not found", srv_config->oauth2_token_name);
        }
    }


    int http_code_response = OK;
    // 1. Retrieve the cookie in header if exists
    char* cookie_value = get_application_cookie_from_header(r, srv_config);
    char* new_cookie_value = NULL;
    redisReply *redis_reply = NULL;
    int user_authenticated = -1;
    if( cookie_value != NULL ) {
        // Retrieve needed infos in Redis :
        //      login, authenticated, doubleauthenticated, headers, krb5ccname, krb5service
        if( get_infos_in_redis_with_cookie_value(srv_config->redis_slave_conn, r, cookie_value, &redis_reply)
            == REDIS_LOST ) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if( redis_reply->element[1]->str != NULL ) {
            user_authenticated = atoi(redis_reply->element[1]->str);
        }
        AP_LOG_DEBUG(r, "Mod_vulture::Cookie given by user and authenticated status=%s", redis_reply->element[1]->str);
    }

    // JJO-24022016: No cookie sent or no cookie found in Redis: Create an anonymous connexion
    //  and redirect to either the portal (authentication) or to the asked uri (tracking mode)
    if( cookie_value == NULL || user_authenticated == -1 ) {

        if( cookie_value != NULL ) {
            AP_LOG_INFO(r, "Mod_vulture::Cookie provided by user, but not found in Redis");
        }

        // Create a new cookie and add it in Redis
        char *url = NULL;
        if( pxy_config->stock_asked_uri_flag == 1 ) {
            // Create absolute url required :
            // pxy_config->url_scheme+pxy_config->application_url.split('/')[0]+r->unparsed_uri
            size_t cpt_tmp = strlen(pxy_config->url_scheme);
            AP_LOG_DEBUG(r, "Mod_vulture::StockAskedUri On");
            while( *(pxy_config->application_url+cpt_tmp) != '/' && *(pxy_config->application_url+cpt_tmp) != '\0' ) {
                cpt_tmp++;
            }
            url = apr_pcalloc(r->pool, cpt_tmp + strlen(r->unparsed_uri) + 1);
            strncpy(url, pxy_config->application_url, cpt_tmp);
            AP_LOG_TRACE1(r, "Mod_vulture::StockAskedUri On: url:'%s'", url);
            strncat(url+cpt_tmp, r->unparsed_uri, strlen(r->unparsed_uri));
            AP_LOG_TRACE1(r, "Mod_vulture::StockAskedUri On: url:'%s'", url);
            url[cpt_tmp + strlen(r->unparsed_uri)] = '\0';
        } else {
            url = pxy_config->application_url;
        }
        new_cookie_value = get_unique_token_in_redis(r->pool);
        AP_LOG_DEBUG(r, "Mod_vulture::Create anonymous connexion for URI : '%s'", url);
        if( add_anonymous_user_in_redis(srv_config->redis_master_conn, pxy_config, r, new_cookie_value, url)
            == REDIS_LOST ) {
            AP_LOG_ALERT(r, "Mod_vulture::register_token_in_redis : Redis connection LOST");
            http_code_response = HTTP_INTERNAL_SERVER_ERROR;
            goto FREE_LABEL;
        }

	    //Authentication is required: Redirect to the portal
        if( pxy_config->authentication_flag == 1 ) {
            http_code_response = redirect_to_portal(r, srv_config, pxy_config, srv_config->redis_master_conn, new_cookie_value);
	        AP_LOG_DEBUG(r, "Mod_vulture::Redirect to portal");
        } else {
            // Anonymous tracking: Redirect to asked URI (forced to 'On' in vulture_application.conf since 1.41) 
            if( pxy_config->stock_asked_uri_flag == 1 ) {
                http_code_response = redirect_to_module(r, srv_config, pxy_config, new_cookie_value, 2);
            } else {
                http_code_response = redirect_to_module(r, srv_config, pxy_config, new_cookie_value, 0);
            }
            AP_LOG_DEBUG(r, "Mod_vulture::Redirect to : '%s'", url);
        }
        goto FREE_LABEL;
    }


    // If specify, update the session timeout
    if( pxy_config->update_session_timeout_flag == 1 ) {
        // EXPIRE returns result->str=NULL => 0 (-1 if connection LOST)
        redisReply *expire_reply = NULL;
        if( perform_redis_query(&srv_config->redis_master_conn, r, &expire_reply, "EXPIRE %s %d",
                                cookie_value, pxy_config->session_timeout) == REDIS_LOST ) {
            AP_LOG_ALERT(r, "Mod_vulture:: Unable to set expiration : Redis master connection LOST");
            http_code_response = HTTP_INTERNAL_SERVER_ERROR;
            goto FREE_LABEL;
        } else {
            AP_LOG_DEBUG(r, "Mod_vulture:: Expiration set for token : %d", pxy_config->session_timeout);
            freeReplyObject(expire_reply);
        }
    }


    // If the app needs authentication and user is not authenticated then redirect to portal
    if( pxy_config->authentication_flag == 1 && user_authenticated != 1 ) {

        http_code_response = redirect_to_portal(r, srv_config, pxy_config, srv_config->redis_slave_conn, cookie_value);
	    AP_LOG_DEBUG(r, "Mod_vulture::Redirect to portal");

        // Release unused variables and redirect the user
        goto FREE_LABEL;
    }


    // If the requested url match disconnect_url regex
    if( pxy_config->authentication_flag == 1 && pxy_config->disconnect_regex == NULL ) {
        AP_LOG_WARNING(r, "Mod_vulture::No valid disconnect URL");
    } else {
        // Regex execute
        int result_regex = ap_regexec(pxy_config->disconnect_regex, r->unparsed_uri, 0, NULL, 0);
        AP_LOG_DEBUG(r, "Mod_vulture::Result of disconnect_url regex: %s", ((result_regex==0) ? "MATCH":
                                                                            ((result_regex==AP_REG_NOMATCH) ? "NO_MATCH":
                                                                             ((result_regex==AP_REG_INVARG) ? "INVARG":
                                                                              ((result_regex==AP_REG_ASSERT) ? "ASSERT":
                                                                               ((result_regex==AP_REG_ESPACE) ? "ESPACE":
                                                                                "UNKNOWN"))))) );
        // Regex match
        if( result_regex == 0 ) {

            // Revoke user's token in Redis
            if( revoke_token_in_redis( r, cookie_value, srv_config->redis_master_conn ) == REDIS_LOST ) {
                http_code_response = HTTP_INTERNAL_SERVER_ERROR;
                goto FREE_LABEL;
            }

            // Create a new cookie and add it in Redis
            char *url = NULL;
            url = pxy_config->application_url;

            new_cookie_value = get_unique_token_in_redis(r->pool);
            if( add_anonymous_user_in_redis(srv_config->redis_master_conn, pxy_config, r, new_cookie_value, url)
                == REDIS_LOST ) {
                AP_LOG_ERROR(r, "Mod_vulture::create_anonymous: Redis connection LOST");
                http_code_response = HTTP_INTERNAL_SERVER_ERROR;
            } else {
                //Never cache anything related to portal
                apr_table_add(r->headers_out, "Cache-Control", "no-cache, no-store, must-revalidate");
                apr_table_add(r->headers_out, "Pragma", "no-cache");
                apr_table_add(r->headers_out, "Expires", "0");

                // Send the cookie to the client and redirect to the module
                http_code_response = redirect_to_module(r, srv_config, pxy_config, new_cookie_value, 1);

                AP_LOG_DEBUG(r, "Mod_vulture::Disconnect: Redirect to application's public path");
            }

            // Release unsed variables and redirect the user
            goto FREE_LABEL;
        }
    }


    // If the application required double authentication,
    // retrieve the doubleauthenticated flag in Redis & verify it
    if( pxy_config->doubleauthentication_flag == 1 ) {
        int user_doubleauthenticated = -1;
        if( redis_reply->element[2]->str != NULL ) {
            user_doubleauthenticated = atoi(redis_reply->element[2]->str);
        }
        //get_doubleauthenticated_flag_in_redis_with_cookie_value(r, cookie_value, srv_config->redis_slave_conn);
        AP_LOG_DEBUG(r, "Mod_vulture::Cookie found and doubleauthenticated status=%d", user_doubleauthenticated);

        // If the user is not double_authenticated then redirect it to the portal
        if( user_doubleauthenticated != 1 ) {
            http_code_response = redirect_to_portal(r, srv_config, pxy_config, srv_config->redis_slave_conn, cookie_value);
            AP_LOG_DEBUG(r, "Mod_vulture::OTP verification is missing, redirect to portal");

            // Release unsed variables and redirect the user
            goto FREE_LABEL;
        }
    }


    //If we are here, we are authenticated and everything is ok

    // If there is/are headers in Redis to send to the requested app, retrieve them
    char *headers_to_send = redis_reply->element[3]->str;

    // And parse/add them to the request object 
    if( headers_to_send != NULL ) {
        r = add_headers_to_send_to_request( r, headers_to_send );
	    headers_to_send = NULL;
    }

    // Retrieve user's login in Redis with token
    char *user_login = redis_reply->element[0]->str;

    // And set it in Request object to log it in access logs
    if( user_login != NULL ) {
        r->user = apr_pstrndup(r->pool, user_login, LOGIN_MAX_SIZE );
        AP_LOG_DEBUG(r, "Mod_vulture::handler: Setting user to : '%s'", user_login);
        user_login = NULL;
        //Also set an environment variable to use it inside Vulture configuration files
	    apr_table_set (r->subprocess_env, "REMOTE_USER", r->user);

        // Perform Kerberos if needed 
        if( pxy_config->kerberos_flag ) {
            // Retrieve kerberos tgt file from Redis
            char *krb5ccname = redis_reply->element[4]->str;
            if( krb5ccname != NULL ) {

                // Retrieve kerberos service from Redis
                char *krb5service = redis_reply->element[5]->str;
                if( krb5service != NULL ) {
                    // Add kerberos tgt base64-encoded in headers_in
                    AP_LOG_DEBUG(r, "Mod_vulture::Retrieving kerberos tgt in cache : %s", \
                                   add_kerberos_tgt_in_header(r, krb5ccname, krb5service) ? "Success" : "Failure" );
                    krb5service = NULL;
                } else {
                    AP_LOG_WARNING(r, "Mod_vulture:handler: Cannot retrieve krb5service from Redis");
                }
                krb5ccname = NULL;
            } else {
                AP_LOG_WARNING(r, "Mod_vulture:handler: Cannot retrieve krb5ccname from Redis");
            }
        }
    } else {
        AP_LOG_WARNING(r, "Mod_vulture:handler: Cannot retrieve user from Redis");
    }
    
    AP_LOG_DEBUG(r, "Mod_vulture::Access the resource");


    // Release unsed variables
    FREE_LABEL:
        freeReplyObject(redis_reply);
    // IMPROVEMENT REV-30 : cookie_value is allocated with apr_pcalloc : no need to free anymore
    // IMPROVEMENT REV-30 : new_cookie_value is allocated with apr_palloc : no need to free anymore

    return http_code_response;
}

