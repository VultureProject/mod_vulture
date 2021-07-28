/**
 * \file     mod_vulture_kerberos.c
 * \authors  Kevin Guillemot, Jeremie Jourdin
 * \version  1.0
 * \date     28/02/17
 * \license  GPLv3
 * \brief    Kerberos wrapper fonctions
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_vulture.h"


/*****************************************/
/* Prototypes of internal file fonctions */
/*****************************************/

/**
 * \brief    Get the detailed exception of major/minor code and log it
 * \details  Convert the major/minor code in char* detailed exception and log it
 * \param    r            The request catched by the handler
 * \param    err_maj      The major code of the exception
 * \param    err_min      The minor code of the exception
 * \return   void
 */
static void set_gss_error(request_rec *r, OM_uint32 err_maj, OM_uint32 err_min);
/**
 * \brief    Log in debug the name in arg
 * \details  Convert the "gss_name_t" struct in char* and log it
 * \param    name         The struct to convert/log
 * \return   void
 */
static void display_name(request_rec *r, gss_name_t *name);


/***************************/
/* Definition of fonctions */
/***************************/

/**
 *  Retrieve kerberos tgt from cache and add it in headers
 */
int add_kerberos_tgt_in_header(request_rec* r, char *krb5ccname, char *krb5service) {
    
    // Status error codes (minor and major)
    OM_uint32 major_status = 0;
    OM_uint32 minor_status = 0;

    /* Import the service name into GSS-API internal format */
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    name.length = strlen(krb5service)+1;
    name.value = (char *)krb5service;
    gss_name_t hostname = GSS_C_NO_NAME;

    major_status = gss_import_name( &minor_status, &name, GSS_C_NT_HOSTBASED_SERVICE, &hostname );
    //gss_release_buffer(&minor_status, &name); //-> SegFault !

    /* If an error occured : free the structures and return 0 */
    if( GSS_ERROR(major_status) )
    {
        set_gss_error(r, major_status, minor_status);
        gss_release_name(&minor_status, &hostname);
        return 0;
    }
    // Display the internal name in debug
    //display_name(r, &hostname);

    /* Retrieve token from cache */
    // Set KRB5CCNAME = tgt file to read
    major_status = gss_krb5_ccache_name(&minor_status, krb5ccname, NULL); 

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc tgt = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    long int gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;

    major_status = gss_init_sec_context( &minor_status, GSS_C_NO_CREDENTIAL, &context, hostname, GSS_C_NO_OID, \
                                        (OM_uint32)gss_flags, 0, GSS_C_NO_CHANNEL_BINDINGS, &input_token, NULL, &tgt, NULL, NULL);

    /* Verify if there was an error in gss_init_sec_context() */
    if ((major_status != GSS_S_COMPLETE) && (major_status != GSS_S_CONTINUE_NEEDED)) {
        // Log error
        AP_LOG_WARNING(r, "gss_init_sec_context() FAILURE");
        set_gss_error(r, major_status, minor_status);
        // Deallocate variables
        gss_release_name(&minor_status, &hostname);
        gss_release_buffer(&minor_status, &tgt);
        gss_release_buffer(&minor_status, &input_token);
        return 0;
    } 

    /* If tgt successfully retrieved */
    if (tgt.length) {
        // Encode-it in base64
        char *base64_tgt = NULL;
        int len_base64_tgt = apr_base64_encode_len(tgt.length);
        base64_tgt = (char*)malloc(len_base64_tgt * sizeof(char));
        apr_base64_encode(base64_tgt, (const char *)tgt.value, tgt.length);
    
        // Try to get the user name if we have completed all GSS operations
        major_status = gss_inquire_context(&minor_status, context, &hostname, NULL, NULL, NULL,  NULL, NULL, NULL);
        // If function fail
        if (GSS_ERROR(major_status)) {
            AP_LOG_WARNING(r, "gss_inquire_context() FAILURE");
            set_gss_error(r, major_status, minor_status);
        } else {
            display_name(r, &hostname);
        }
        /* Add base64_tgt in header : "Authorization : Negotiate "+token */ 	
        if( strlen(base64_tgt) > HEADER_MAX_SIZE ) {
            AP_LOG_ERROR( r, "Attempting to overflow the Kerberos 'Authorization' header ! Headers max size is %d (%lu bytes requested)", HEADER_MAX_SIZE, strlen(base64_tgt));
        }
        // Forge Authorization header content
        char *header = NULL;
        header = (char *)malloc( (HEADER_MAX_SIZE+1) *sizeof(char));
        snprintf(header, HEADER_MAX_SIZE, "Negotiate %s", base64_tgt);

        // Add it to the headers_in
        apr_table_add( r->headers_in, "Authorization", header);
    }
 
    // Deallocate variables   
    gss_release_name(&minor_status, &hostname);
    gss_release_buffer(&minor_status, &tgt);
    gss_release_buffer(&minor_status, &input_token);

    return 1;
}

/**
 *  Log a kerberos error with its major and minor status code
 */
static void set_gss_error(request_rec *r, OM_uint32 err_maj, OM_uint32 err_min) {

    OM_uint32 maj_stat = 0, min_stat = 0;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string = GSS_C_EMPTY_BUFFER;
    char buf_maj[MAX_EXCEPTION_MAJOR+1];
    char buf_min[MAX_EXCEPTION_MINOR+1];

    do {
        /* Retrieve major status code information */
        maj_stat = gss_display_status (&min_stat,
                                       err_maj,
                                       GSS_C_GSS_CODE,
                                       GSS_C_NO_OID,
                                       &msg_ctx,
                                       &status_string);
        // If an error occured, log error and quit the loop
        if (GSS_ERROR(maj_stat)) {
            AP_LOG_ERROR(r, "KERBEROS::Unable to retrieve exception information.");
            break;
        }
        // Copy the error in buffer
        strncpy(buf_maj, (char*)status_string.value, MAX_EXCEPTION_MAJOR);
        // Deallocate temporal buffer
        gss_release_buffer(&min_stat, &status_string);

        /* Retrieve minor status code information */
        maj_stat = gss_display_status (&min_stat,
                                       err_min,
                                       GSS_C_MECH_CODE,
                                       GSS_C_NULL_OID,
                                       &msg_ctx,
                                       &status_string);
        // If the function success
        if (!GSS_ERROR(maj_stat)) {
            // Copy the error in buffer
            strncpy(buf_min, (char*) status_string.value, MAX_EXCEPTION_MINOR);
            // Deallocate temporal buffer
            gss_release_buffer(&min_stat, &status_string);
        }
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
    // Log exception informations
    AP_LOG_WARNING(r, "KERBEROS_Exception_details : ((%s:%d)(%s:%d))", buf_maj, err_maj, buf_min, err_min);
}

/**
 *  Log the internal name "gss_name_t" struct
 */
static void display_name(request_rec *r, gss_name_t *name) {

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_buffer_desc out_name;
    // Retrieve the name in "out_name"
    maj_stat = gss_display_name(&min_stat, *name, &out_name, NULL);
    // If an error occured
    if (maj_stat != GSS_S_COMPLETE) {
        AP_LOG_NOTICE(r, "gss_display_name FAILURE");
        set_gss_error(r, maj_stat, min_stat);
    } else {
        AP_LOG_DEBUG(r, "Name of user's tgt : '%s'", (char *)out_name.value);
    }
    // Deallocate temp struct
    gss_release_buffer(&min_stat, &out_name);
}

