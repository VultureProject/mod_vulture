/**
 * \file     kerberos_client.h
 * \author   Kevin Guillemot
 * \version  1.0
 * \date     12/05/2016
 * \license  GPLv3
 * \brief    Header file needed for kerberos performing in mod_vulture
 */

#ifndef VULTURE_ENGINE_KERBEROS_CLIENT_H
#define VULTURE_ENGINE_KERBEROS_CLIENT_H


/*************/
/* Constants */
/*************/

/**
 * \def MAX_EXCEPTION_MAJOR
 *      The maximum length of a Kerberos major detailed exception
 */
#define MAX_EXCEPTION_MAJOR 128

/**
 * \def MAX_EXCEPTION_MINOR
 *      The maximum length of a Kerberos minor detailed exception
 */
#define MAX_EXCEPTION_MINOR 128

/**
 * \def KRB5CCNAME_MAX_SIZE
 *      The maximum length of the 'krb5ccname' value in Redis : "FILE:/tmp/krb5cc_"+SHA1() = 58
 */
#define KRB5CCNAME_MAX_SIZE 58

/**
 * \def KRB5SERVICE_MAX_SIZE
 *      The maximum length of the 'krb5service' value in Redis : arbitrary value of 64
 */
#define KRB5SERVICE_MAX_SIZE 64


/************************/
/* Functions signatures */
/************************/

/**
 * \brief    Retrieve a kerberos tgt in specified file
 * \details  Get a kerberos tgt in cache_file and add it base64_encoded in headers_in
 * \param    r            The request catched by the handler
 * \param    krb5ccname   The file that contain the tgt
 * \param    krb5service  The service used to create the tgt
 * \return   1 if success, 0 otherwise
 */
int add_kerberos_tgt_in_header(request_rec* r, char *krb5ccname, char *krb5service);


#endif //VULTURE_ENGINE_KERBEROS_CLIENT_H

