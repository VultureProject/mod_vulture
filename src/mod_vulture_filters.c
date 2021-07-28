/**
 * \file     mod_vulture_filters.c
 * \authors  Kevin Guillemot
 * \version  1.0
 * \date     19/10/17
 * \license  GPLv3
 * \brief    mod_vulture filters
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_vulture.h"
#include "modsecurity.h"


/***************************/
/* Definition of fonctions */
/***************************/

/**
 *  Retrieve SVMs env variables and set JSON message and anomaly score depending on
 *      Returns the calculated anomaly score
 */
static int perform_svm_triggered(int anomaly_score, apr_table_t *environment, char *message, int warning_anomaly_score) {
    char *message_ptr = message;
    const char *tmp = NULL;
    if( (tmp=apr_table_get(environment, "svm4")) != NULL && *(tmp) == '1' ) {
        anomaly_score += warning_anomaly_score; // SVM4 => WARNING
        message_ptr = stpncpy(message_ptr, "\\\"SVM 4 triggered\\\",", 24);
    }
    if( (tmp=apr_table_get(environment, "svm5")) != NULL && *(tmp) == '1' ) {
        anomaly_score += warning_anomaly_score; // SVM5 => NOTICE
        message_ptr = stpncpy(message_ptr, "\\\"SVM 5 triggered\\\",", 24);
    }

    if( message != message_ptr )
        *(message_ptr-1) = 0x00;

    return anomaly_score;
}

/**
 *  Write html content and headers of an HTTP FORBIDDEN
 *      Returns the modified request
 */
static request_rec *write_403(apr_bucket_brigade *bb, request_rec *r) {
    /* Clear and set headers */
    apr_table_clear(r->headers_out);
    /* Set new required headers */
    apr_table_set(r->headers_out, "Content-Length", apr_ltoa(r->pool, LEN_403 + strlen(r->uri)));
    ap_set_content_type(r, "text/html; charset=UTF-8");
    /* Writing 403 Forbidden */
    r->status = HTTP_FORBIDDEN;
    apr_brigade_printf(bb, NULL, NULL, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>403 Forbidden</title>\n"
            "</head><body>\n"
            "<h1>Forbidden</h1>\n"
            "<p>You don't have permission to access %s on this server.</p>\n"
            "<br><hr>\n"
            "<address>Vulture server</address>\n"
            "</body></html>\n", r->uri);
    return r;
}

/**
 *  Write html content and headers of an HTTP FORBIDDEN
 *      Returns the modified request
 */
static int retrieve_tx_var(apr_table_t *tx_vars, const char *key, request_rec *r) {
    msc_string *value_str = NULL;
    if( (value_str=(msc_string*)apr_table_get(tx_vars, key)) == NULL ) {
        AP_LOG_WARNING(r, "Mod_vulture::Output_filter: Failed to retrieve %s from tx vars", key);
        return -1;
    }
    int value = atoi(value_str->value);
    AP_LOG_DEBUG(r, "Mod_vulture::Output_filter: %s = %d", key, value);
    return value;
}

/**
 *  Implementation of the mod_vulture output_filter logic
 *
 */
apr_status_t vulture_output_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    if( f->r->status == HTTP_FORBIDDEN ) {
        AP_LOG_DEBUG(f->r, "Mod_vulture::Output_filter: HTTP status code = 403, no need to perform");
        goto END;
    }

    /* Retrieve modsec_rec structure from notes */
    modsec_rec *msr = NULL;
    if( (msr=(modsec_rec *)apr_table_get(f->r->notes, NOTE_MSR)) == NULL ) {
        AP_LOG_ERROR(f->r, "Mod_vulture::Output_filter: Failed to retrieve modsec_rec structure");
        goto END;
    }

    /* Retrieve inbound_anomaly_score from modsec_rec tx_vars */
    int inbound_score = 0;
    if( (inbound_score=retrieve_tx_var(msr->tx_vars, INBOUND_SCORE_TX, f->r)) < 0 )
        goto END;
    /* Retrieve warning_anomaly_score from modsec_rec tx_vars */
    int warning_score = 0;
    if( (warning_score=retrieve_tx_var(msr->tx_vars, WARNING_SCORE_TX, f->r)) < 0 )
        goto END;

    /* Build json structure depending on SVM env &
     *   Increment inbound_anomaly_score depending on SVM 4,5,6,7 results */
    char svm_msg[24*6] = {0}; // strlen("SVM ? triggered") * nombre de SVMs
    inbound_score = perform_svm_triggered(inbound_score, f->r->subprocess_env, svm_msg, warning_score);
    /* Set the calculated inbound_anomaly_score in environnement to log */
    AP_LOG_DEBUG(f->r, "Mod_vulture::Output_filter: New inbound_anomaly_score = %d", inbound_score);
    apr_table_set(msr->r->subprocess_env, "score", apr_psprintf(msr->mp, "%d", inbound_score));

    /* Set "reason" environment variable with svm_msg */
    const char *reasons = NULL;
    char *new_reason = NULL;
    new_reason = ( (reasons=apr_table_get(msr->r->subprocess_env, "reasons")) == NULL ) ?
                    (apr_psprintf(f->r->pool, "[%s]", svm_msg)) :
                    (apr_psprintf(f->r->pool, "%.*s,%s]", (int)(strlen(reasons) - 1), reasons, svm_msg));
    AP_LOG_DEBUG(f->r, "Mod_vulture::Output_filter: Setting env variable \"reason\" : %s", new_reason);
    apr_table_set(msr->r->subprocess_env, "reasons", new_reason);

    /* Retrieve inbound_anomaly_score_threshold from env */
    int inbound_threshold = 0;
    if( (inbound_threshold=retrieve_tx_var(msr->tx_vars, THRESHOLD_SCORE_TX, f->r)) < 0 )
        goto END;
    /* Set the inbound_anomaly_threshold in environment to log */
    apr_table_set(msr->r->subprocess_env, "threshold", apr_psprintf(f->r->pool, "%d", inbound_threshold));


    /* If anomaly score exceed threshold */
    if( inbound_score >= inbound_threshold ) {
        /* Return 403 */
        AP_LOG_ERROR(f->r, "Mod_vulture::Output_filter: Anomaly score %d exceed threshold (%d) => Blocking request !", inbound_score, inbound_threshold);
        apr_bucket_brigade *tmpbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        f->r = write_403(tmpbb, f->r);
        APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_eos_create(f->c->bucket_alloc));
        apr_status_t rc = APR_SUCCESS;
        if( (rc=ap_pass_brigade(f->next, tmpbb)) != APR_SUCCESS) {
            AP_LOG_ERROR(f->r, "Mod_vulture::Output_filter: Unable to pass 403 brigade");
            return rc;
        }
        AP_LOG_DEBUG(f->r, "Mod_vulture::Output_filter: Cleaning-up brigades");
        apr_brigade_cleanup(bb); // bb ?
        apr_brigade_cleanup(tmpbb); // bb ?
        return APR_SUCCESS;
    }

    END:
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}