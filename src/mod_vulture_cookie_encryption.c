/**
 * \file     mod_vulture_cookie_encryption.c
 * \authors  Hugo Soszynski
 * \version  1.0
 * \date     01/12/17
 * \license  GPLv3
 * \brief   mod_vulture cookie encryption
 */

#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <mod_vulture.h>


/*---------*/
/*  Utils  */
/*---------*/
/**
 * Count the number of cookies in str.
 * str MUST be in a cookie format.
 *
 * \param str A pointer to the string containing the cookies.
 * \return The number of cookie in the string.
 */
static size_t count_cookies(const char* str) {
    size_t count = 0;
    int flag = 0;

    for (size_t i = 0; str[i] != '\0'; ++i) {
	if (isspace(str[i]))
	    continue;
	if (!flag && str[i] != ';') {
	    flag = !flag;
	    continue;
	}
	if (flag && str[i] == ';') {
	    ++count;
	    flag = !flag;
	}
    }
    if (flag)
	count++;
    return count;
}

/**
 * Return a pointer to th cookie value after separating the name and the value
 * by replacing '=' by '\0'. Modify str.
 *
 * \param str A pointer to the name of the cookie. (format: "name=value")
 * \return A pointer to the cookie value.
 */
static char* get_cookie_value(char* str) {
    for (size_t i = 0; str[i] != '\0'; ++i) {
	if (str[i] == '=' && str[i + 1] != '\0') {
	    str[i] = '\0';
	    return &(str[i + 1]);
	}
    }
    return NULL;
}

/**
 * Get the length of the cookie part. Delimited by =, ; or \0.
 *
 * \param cookie The cookie.
 * \return The found length of the cookie name.
 */
static inline size_t get_cookie_part_len(const char* cookie) {
    size_t len = 0;

    while (cookie[len] != '=' && cookie[len] != '\0' && cookie[len] != ';')
	++len;
    return len;
}

/**
 * Parse the cookie and get the value. Modify the cookie_chain.
 *
 * \param cookie_chain The Starting of the cookie chain.
 * \param *cookie_value Pointer to the value (NULL in error case). Can point to empty string.
 * \return Pointer to the next cookie. NULL if there is no more cookie. NULL if there is a format error (along *cookie_value).
 */
static char* get_next_cookie(char* cookie_chain, char** cookie_value) {
    size_t cpt;
    char* next = NULL;

    for (cpt = 0; cookie_chain[cpt] != '=' &&
		  cookie_chain[cpt] != ';' &&
		  cookie_chain[cpt] != '\0'; ++cpt);
    if (cookie_chain[cpt] != '=')
	return NULL;
    cookie_chain[cpt] = '\0';
    ++cpt;
    *cookie_value = cookie_chain + cpt;
    for (; cookie_chain[cpt] != ';' && cookie_chain[cpt] != '\0'; ++cpt);
    if (cookie_chain[cpt] == ';'){
	cookie_chain[cpt] = '\0';
	if (cookie_chain[++cpt] != '\0') {
	    for (; cookie_chain[cpt] != ' ' && cookie_chain[cpt] != '\0'; ++cpt);
	    if (cookie_chain[cpt] != '\0')
		next = &cookie_chain[cpt];
	}
    }
    return next;
}

/**
 * Concat two string with the standard http cookie separation '; '
 *
 * \param s The destination string. Must be large enough to contain the two strings and the standard http cookie separation.
 * \param append The string to append. appends not more than n characters from append, and then adds a terminating `\0'.
 * \param n The max number of byte from the append string to append to the s string.
 * \return Return the pointer s.
 */
static inline char* cookiencat(char* s, const char* append, size_t n) {
    if (strlen(s) > 0)
	strncat(s, "; ", 2);
    strncat(s, append, n);
    return s;
}

/**
 * Concat the name and the value of a cookie to make a full standard cookie.
 *
 * \param p The pool for allocations.
 * \param name The name of the cookie.
 * \param value The value of the cookie.
 * \return A newly allocated string containing the formatted cookie.
 */
static char* cookie_nameval_concat(apr_pool_t* p, const char* name,
				   const char* value) {
    char* cookie = NULL;
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);

    if ((cookie = apr_pcalloc(p, name_len + value_len + 2)) == NULL)
	return NULL;
    strncpy(cookie, name, name_len);
    cookie[name_len] = '=';
    strncat(cookie, value, value_len);
    return cookie;
}

/*---------------------*/
/*  Cookie Encryption  */
/*---------------------*/
/**
 * AES and Base64 Encode a String.
 *
 * \param p The pool for allocations.
 * \param str The string to encode.
 * \param len The length of the string to encode.
 * \return A pointer on the first char of the encoded string (newly allocated). NULL on error.
 */
static char* encrypt_str(apr_pool_t* p, const char* str,
			 const size_t len, proxy_config* conf, request_rec* r) {
    char* tmp = NULL;
    char* out = NULL;
    int block_size = 0;
    size_t tmp_len = 0;
    size_t out_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char* buf = NULL;

    EVP_EncryptInit(ctx, OPENSSL_CIPHERS[conf->cipher](),
		   (unsigned char*)conf->cipher_key,
		   (unsigned char*)conf->cipher_iv);
    block_size = EVP_CIPHER_CTX_block_size(ctx);
    if ((buf = apr_pcalloc(p, len + block_size)) == NULL)
	return NULL;
    if ((tmp = apr_pcalloc(p, len + block_size)) == NULL)
	return NULL;
    EVP_EncryptUpdate(ctx, (unsigned char*)tmp, (int*)&tmp_len, (unsigned char*)str, (int)len);
    EVP_EncryptFinal(ctx, buf, (int*)&out_len);
    if ((out = apr_pcalloc(p, out_len + tmp_len + 1)) == NULL)
	return NULL;

    memcpy(out, tmp, tmp_len);
    memcpy(out + tmp_len, buf, out_len);
    out_len += tmp_len;
    tmp_len = out_len;
    tmp = out;
    out_len = (size_t)apr_base64_encode_len((int)out_len);
    if ((out = apr_pcalloc(p, out_len + 1)) == NULL)
	return NULL;
    apr_base64_encode(out, tmp, (int)tmp_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    for (int i = 0; out[i] != '\0'; ++i)
	if (out[i] == '=')
	    out[i] = '-';
    return out;
}

/**
 * Concat the name, the value and the params of a cookie to make a full standard Set-Cookie.
 * Output format: "<name>=<value>; <params>"
 *
 * \param p The pool for allocations.
 * \param name The name of the cookie.
 * \param value The value of the cookie.
 * \param params The params of the cookie.
 * \return A newly allocated string containing the formatted cookie.
 */
static char* build_set_cookie(apr_pool_t* p, const char* name,
			      const char* value, const char* params) {
    char* cookie = NULL;
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    size_t params_len = strlen(params);

    if ((cookie = apr_pcalloc(p, name_len + value_len + params_len + 4)) == NULL)
	return NULL;
    stpncpy(
	stpncpy(
	    stpncpy(
		stpncpy(
		    stpncpy(cookie, name, name_len),
		    "=", 1),
		value, value_len),
	    "; ", 2),
	params, params_len);
    return cookie;
}

/**
 * Callback for apr_table_do function.
 * Add the key value pair to the table.
 *
 * \param v The table (apr_table_t*).
 * \param key The key to store.
 * \param val The value to store.
 * \return Non-zero to continue to loop.
 */
static int add_them_all(void *v, const char *key, const char *val) {
    apr_table_t *headers = (apr_table_t *)v;

    apr_table_add(headers, key, val);
    return 1;
}

/**
 * Encrypt all the Set-Cookie headers using aes256 and base64.
 *
 * \param r The Apache request object.
 */
static void do_cookie_encryption(request_rec* r, proxy_config* conf) {
    server_config* srvconf = (server_config *) ap_get_module_config(r->server->module_config , &vulture_module);
    const apr_array_header_t* fields = apr_table_elts(r->headers_out);
    apr_table_entry_t* entry = (apr_table_entry_t *) fields->elts;
    char* cookie_val = NULL;
    char* cookie_name = NULL;
    apr_table_t* table = NULL;
    char* cookie_params = NULL;
    size_t cookie_name_len = 0;
    char* enc_cookie_val = NULL;
    char* enc_cookie_name = NULL;


    // Iteration over the headers of the response to get all the Set-Cookie
    for (int i = 0; i < fields->nelts; ++i) {

	if (strncmp(entry[i].key, "Set-Cookie\0", 11) != 0) {
	    continue;
	}
	cookie_name = entry[i].val;
	cookie_name_len = get_cookie_part_len(cookie_name);

	// Omitting the vulture's cookies (No need for encryption)
	if (conf->authentication_flag || conf->tracking_flag){
	    if (cookie_name == NULL ||
		(cookie_name_len == strlen(srvconf->cookie_name) &&
		 !strncmp(cookie_name, srvconf->cookie_name, cookie_name_len)) ||
		(cookie_name_len == strlen(srvconf->portal_cookie_name) &&
		 !strncmp(cookie_name, srvconf->portal_cookie_name, cookie_name_len)) ||
                (cookie_name_len == strlen("csrftk") &&
                 !strncmp(cookie_name, "csrftk", cookie_name_len))) {
		continue;
	    }
	}


	if (!table)
	    table = apr_table_make(r->pool, fields->nelts - i);
	cookie_name = apr_pstrdup(r->pool, cookie_name);

	// Getting the cookie value.
	if ((cookie_params = get_next_cookie(cookie_name, &cookie_val)) == NULL &&
	    cookie_val == NULL) {
	    AP_LOG_ERROR(r, "ModVulture: do_cookie_encryption: Set-Cookie format error");
	    continue;
	}

	// Encrypt key
	if ((enc_cookie_name = encrypt_str(r->pool, cookie_name,
					   cookie_name_len, conf, r)) == NULL) {
	    AP_LOG_ERROR(r, "ModVulture: do_cookie_encryption: Memory Allocation Error");
	    apr_table_add(table, "Set-Cookie", entry[i].val);
	    continue;
	}

	// Encrypt value
	if ((enc_cookie_val = encrypt_str(r->pool, cookie_val,
					  strlen(cookie_val), conf, r)) == NULL) {
	    AP_LOG_ERROR(r, "ModVulture: do_cookie_encryption: Memory Allocation Error");
	    apr_table_add(table, "Set-Cookie", entry[i].val);
	    continue;
	}

	// Concat name + '=' + value + '; ' + params
	if ((enc_cookie_name = build_set_cookie(r->pool,
						enc_cookie_name,
						enc_cookie_val,
						cookie_params)) == NULL) {
	    AP_LOG_ERROR(r, "ModVulture: do_cookie_encryption: Memory Allocation Error");
	    apr_table_add(table, "Set-Cookie", entry[i].val);
	    continue;
	}

	// Everything went well, we can add the encrypted cookie to the table
	apr_table_add(table, "Set-Cookie", enc_cookie_name);
    }
    // Now we remove all the Set-Cookie and add the encrypted ones
    if (table) {
	apr_table_unset(r->headers_out, "Set-Cookie");
	apr_table_do(add_them_all, (void*)r->headers_out, table, NULL);
    }
}

/*---------------------*/
/*  Cookie Decryption  */
/*---------------------*/

/**
 * Decrypt a string encrypted by the encrypt_str function.
 *
 * \param p The pool to use for allocation.
 * \param str The string to decrypt.
 * \param conf The configuration.
 * \return A newly allocated string containing the plain text message.
 */
static char* decrypt_str(apr_pool_t* p, char* str, proxy_config* conf, request_rec* r) {
    int plain_len = 0;
    int tmp_len = 0;
    char* plain = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char* decode = NULL;
    size_t outlen_max = 0;

    for (int i = 0; str[i] != '\0'; ++i)
	if (str[i] == '-')
	    str[i] = '=';
    outlen_max = (size_t)apr_base64_decode_len(str) + 1;
    if ((decode = apr_pcalloc(p, outlen_max + 1)) == NULL)
	return NULL;
    if ((plain = apr_pcalloc(p, outlen_max + 1)) == NULL)
	return NULL;
    outlen_max = (size_t)apr_base64_decode(decode, str);
    EVP_DecryptInit(ctx, OPENSSL_CIPHERS[conf->cipher](),
		    (unsigned char*)conf->cipher_key,
		    (unsigned char*)conf->cipher_iv);
    EVP_DecryptUpdate(ctx, (unsigned char*)plain, &tmp_len,
		      (unsigned char*)decode, (int)outlen_max);
    EVP_DecryptFinal(ctx, (unsigned char*)plain + tmp_len, &plain_len);
    EVP_CIPHER_CTX_cleanup(ctx);
    return plain;
}

/**
 * Decrypt all the cookies in the Cookie header.
 *
 * \param r The apache request object to work on.
 * \param conf The conf to work with.
 */
static void do_cookie_decryption(request_rec* r, proxy_config* conf) {
    server_config* srvconf = (server_config *) ap_get_module_config(r->server->module_config , &vulture_module);
    const apr_array_header_t* fields = apr_table_elts(r->headers_in);
    apr_table_entry_t* entry = (apr_table_entry_t *) fields->elts;
    char* tok = NULL;
    char* value = NULL;
    char* cookie = NULL;
    size_t no_cookie = 0;
    char* dec_name = NULL;
    size_t cookie_nbr = 0;
    char* dec_value = NULL;
    char* new_cookie = NULL;
    char* plain_cookie = NULL;
    size_t new_cookie_len = 1;
    char** plain_cookies = NULL;

    for (int i = 0; i < fields->nelts; ++i) {

	// Isolating the Cookie header
	if (!strncmp("Cookie\0", entry[i].key, 7)) {

	    if ((cookie = apr_pstrdup(r->pool, entry[i].val)) == NULL)
		return;
	    if ((cookie_nbr = count_cookies(cookie)) == 0)
		return;
	    if ((plain_cookies = apr_pcalloc(r->pool, (cookie_nbr + 1) * sizeof(char*))) == NULL)
		return;

	    // Iterating over the received cookies
            char* save_ptr = NULL;
	    tok = strtok_r(cookie, "; ", &save_ptr);
	    while (tok != NULL && no_cookie < cookie_nbr) {
		if ((value = get_cookie_value(tok)) == NULL)
		    return;

                if ((conf->authentication_flag || conf->tracking_flag) &&
                    (strncmp("csrftk", tok, strlen("csrftk")) == 0 ||
                     strncmp(srvconf->portal_cookie_name, tok, strlen(srvconf->portal_cookie_name)) == 0 ||
                     strncmp(srvconf->cookie_name, tok, strlen(srvconf->cookie_name)) == 0)) {

                    // Adding the Vultures cookies to the cookie list
                    if ((plain_cookies[no_cookie] = cookie_nameval_concat(r->pool, tok, value)) == NULL)
                        return;
                    new_cookie_len += strlen(plain_cookies[no_cookie]) + 2;
                }
                else {
                    // Decrypt Name
                    if ((dec_name = decrypt_str(r->pool, tok, conf, r)) == NULL)
                        return;

                    // Decrypt Value
                    if ((dec_value = decrypt_str(r->pool, value, conf, r)) == NULL)
                        return;

                    // Concat decrypted name and value to have a full cookie
                    if ((plain_cookie = cookie_nameval_concat(r->pool, dec_name, dec_value)) == NULL)
                        return;

                    // Add the decrypted reformatted cookie to the cookie list
                    plain_cookies[no_cookie] = plain_cookie;
                    new_cookie_len += strlen(plain_cookie) + 2;
                }
		++no_cookie;
		tok = strtok_r(NULL, "; ", &save_ptr);
	    }
	    if ((new_cookie = apr_pcalloc(r->pool, new_cookie_len + 1)) == NULL)
		return;
	    for (size_t j = 0; j < cookie_nbr; ++j) {
		cookiencat(new_cookie, plain_cookies[j], strlen(plain_cookies[j]));
	    }
	    apr_table_unset(r->headers_in, "Cookie");
	    apr_table_set(r->headers_in, "Cookie", new_cookie);
	    return;
	}
    }
}

/*---------------------------*/
/*   Post Read Request Hook  */
/*---------------------------*/

apr_status_t vulture_cookie_encryption_prr_hook(request_rec* r) {
    proxy_config* pxy_config =
	(proxy_config *)ap_get_module_config(r->per_dir_config,
					     &vulture_module);

    /* If there is any missing configuration, do not activate cookie encryption */
    if (pxy_config->cookie_encryption_flag &&
	pxy_config->cipher > NONE &&
	pxy_config->cipher < NBR_CIPHERS &&
	strlen(pxy_config->cipher_key) &&
	strlen(pxy_config->cipher_iv)) {
	do_cookie_decryption(r, pxy_config);
    }
    return OK;
}

/*-----------------*/
/*  Output Filter  */
/*-----------------*/
/**
 * Decide to do the cookie encryption or not and pass to the next filter.
 *
 * \param f Apache filter structure to work on.
 * \param in Apache brigade to work with.
 * \return Status of passing the next filter in the stack.
 */
apr_status_t vulture_cookie_encryption_output_filter(ap_filter_t* f,
						     apr_bucket_brigade* in) {
    proxy_config* pxy_config =
	(proxy_config *) ap_get_module_config(f->r->per_dir_config,
					      &vulture_module);

    /* If there is any missing configuration, do not activate cookie encryption */
    if (pxy_config->cookie_encryption_flag &&
	pxy_config->cipher > NONE &&
	pxy_config->cipher < NBR_CIPHERS &&
	strlen(pxy_config->cipher_key) &&
	strlen(pxy_config->cipher_iv)) {
	do_cookie_encryption(f->r, pxy_config);
    }
    return ap_pass_brigade(f->next, in);
}