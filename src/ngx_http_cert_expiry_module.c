/*
 * Copyright (c) 2026, Jochen Neumeister <joneum@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY DAMAGES WHATSOEVER ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


typedef struct {
    ngx_array_t  *files;        /* of ngx_str_t, every ssl_certificate */
    ngx_msec_t    interval;     /* how often the check runs again */
    time_t        warn;         /* warn below this many seconds left */
} ngx_http_cert_expiry_main_conf_t;


static ngx_int_t ngx_http_cert_expiry_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cert_expiry_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_cert_expiry_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_cert_expiry_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_cert_expiry_postconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_cert_expiry_init_process(ngx_cycle_t *cycle);
static void ngx_http_cert_expiry_exit_process(ngx_cycle_t *cycle);
static void ngx_http_cert_expiry_timer(ngx_event_t *ev);
static void ngx_http_cert_expiry_check(ngx_log_t *log);
static ngx_int_t ngx_http_cert_expiry_left(ngx_str_t *file, time_t *left,
    ngx_log_t *log);


static ngx_command_t  ngx_http_cert_expiry_commands[] = {

    { ngx_string("cert_expiry_warn"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cert_expiry_main_conf_t, warn),
      NULL },

    { ngx_string("cert_expiry_check"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cert_expiry_main_conf_t, interval),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cert_expiry_module_ctx = {
    ngx_http_cert_expiry_add_variables,     /* preconfiguration */
    ngx_http_cert_expiry_postconf,          /* postconfiguration */

    ngx_http_cert_expiry_create_main_conf,  /* create main configuration */
    ngx_http_cert_expiry_init_main_conf,    /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_cert_expiry_module = {
    NGX_MODULE_V1,
    &ngx_http_cert_expiry_module_ctx,       /* module context */
    ngx_http_cert_expiry_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_http_cert_expiry_init_process,      /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_cert_expiry_exit_process,      /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_event_t   ngx_http_cert_expiry_event;
static ngx_array_t  *ngx_http_cert_expiry_files;
static time_t        ngx_http_cert_expiry_warn;


static ngx_str_t  ngx_http_cert_expiry_name =
    ngx_string("ssl_expiry_days");


/*
 * Days left on the certificate this connection was served with.  Not the
 * configured file but the one OpenSSL picked, which is the honest answer
 * when a server carries an RSA and an ECDSA certificate at once.
 */
static ngx_int_t
ngx_http_cert_expiry_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char     *p;
    time_t      left;
    X509       *cert;
    int         days, seconds;
    ASN1_TIME  *notafter;

    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    cert = SSL_get_certificate(r->connection->ssl->connection);
    if (cert == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    notafter = X509_getm_notAfter(cert);
    if (notafter == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!ASN1_TIME_diff(&days, &seconds, NULL, notafter)) {
        v->not_found = 1;
        return NGX_OK;
    }

    left = (time_t) days;

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", left) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cert_expiry_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_cert_expiry_name,
                                NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cert_expiry_variable;

    return NGX_OK;
}


/*
 * How many seconds the certificate in this file has left.  The file is
 * read rather than asked of the SSL context, because a context hands back
 * one certificate while a server may have been given several, and because
 * this has to work before a single handshake has happened.
 */
static ngx_int_t
ngx_http_cert_expiry_left(ngx_str_t *file, time_t *left, ngx_log_t *log)
{
    BIO        *bio;
    X509       *cert;
    int         days, seconds;
    ASN1_TIME  *notafter;

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: cannot open \"%V\"", file);
        return NGX_ERROR;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);

    if (cert == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: \"%V\" holds no PEM certificate", file);
        return NGX_ERROR;
    }

    notafter = X509_getm_notAfter(cert);

    if (notafter == NULL || !ASN1_TIME_diff(&days, &seconds, NULL, notafter)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: \"%V\" has no readable notAfter", file);
        X509_free(cert);
        return NGX_ERROR;
    }

    X509_free(cert);

    *left = (time_t) days * 86400 + seconds;

    return NGX_OK;
}


static void
ngx_http_cert_expiry_check(ngx_log_t *log)
{
    time_t      left;
    ngx_str_t  *file;
    ngx_uint_t  i;

    if (ngx_http_cert_expiry_files == NULL) {
        return;
    }

    file = ngx_http_cert_expiry_files->elts;

    for (i = 0; i < ngx_http_cert_expiry_files->nelts; i++) {

        if (ngx_http_cert_expiry_left(&file[i], &left, log) != NGX_OK) {
            continue;
        }

        if (left <= 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "certificate \"%V\" expired %T days ago",
                          &file[i], (time_t) (-left / 86400));
            continue;
        }

        if (left <= ngx_http_cert_expiry_warn) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "certificate \"%V\" expires in %T days",
                          &file[i], (time_t) (left / 86400));
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "certificate \"%V\" is good for %T more days",
                      &file[i], (time_t) (left / 86400));
    }
}


static void
ngx_http_cert_expiry_timer(ngx_event_t *ev)
{
    ngx_http_cert_expiry_check(ev->log);

    if (!ngx_exiting && !ngx_terminate && !ngx_quit) {
        ngx_add_timer(ev, (ngx_msec_t) (uintptr_t) ev->data);
    }
}


static ngx_int_t
ngx_http_cert_expiry_init_process(ngx_cycle_t *cycle)
{
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_cert_expiry_module);

    if (cemcf == NULL || ngx_http_cert_expiry_files == NULL
        || ngx_http_cert_expiry_files->nelts == 0)
    {
        return NGX_OK;
    }

    /*
     * One worker does the checking.  Every worker reading the same files
     * and writing the same warning would say the same thing as often as
     * the server has workers, which makes the log harder to read, not the
     * certificate fresher.
     */
    if (ngx_process == NGX_PROCESS_WORKER && ngx_worker != 0) {
        return NGX_OK;
    }

    ngx_http_cert_expiry_check(cycle->log);

    ngx_http_cert_expiry_event.handler = ngx_http_cert_expiry_timer;
    ngx_http_cert_expiry_event.log = cycle->log;
    ngx_http_cert_expiry_event.data = (void *) (uintptr_t) cemcf->interval;
    ngx_http_cert_expiry_event.cancelable = 1;

    ngx_add_timer(&ngx_http_cert_expiry_event, cemcf->interval);

    return NGX_OK;
}


static void
ngx_http_cert_expiry_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_http_cert_expiry_event.timer_set) {
        ngx_del_timer(&ngx_http_cert_expiry_event);
    }
}


static void *
ngx_http_cert_expiry_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cert_expiry_main_conf_t));
    if (cemcf == NULL) {
        return NULL;
    }

    cemcf->warn = NGX_CONF_UNSET;
    cemcf->interval = NGX_CONF_UNSET_MSEC;

    return cemcf;
}


static char *
ngx_http_cert_expiry_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_cert_expiry_main_conf_t  *cemcf = conf;

    /* a fortnight, which is what an ACME client has already failed at */
    ngx_conf_init_value(cemcf->warn, 14 * 86400);

    /* twice a day: often enough to catch a renewal that did not happen */
    ngx_conf_init_msec_value(cemcf->interval, 12 * 60 * 60 * 1000);

    return NGX_CONF_OK;
}


/*
 * Collect every file named by an ssl_certificate, once.  The list is built
 * here, in the master, so a worker never walks the configuration and never
 * allocates for this again.
 */
static ngx_int_t
ngx_http_cert_expiry_postconf(ngx_conf_t *cf)
{
    ngx_str_t                         *certs, *file, full;
    ngx_uint_t                         i, j, k, seen;
    ngx_http_ssl_srv_conf_t           *sscf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_cert_expiry_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    cemcf->files = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (cemcf->files == NULL) {
        return NGX_ERROR;
    }

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {

        sscf = cscfp[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf == NULL || sscf->certificates == NULL) {
            continue;
        }

        if (sscf->certificate_values != NULL) {
            /*
             * The file name carries variables, so it is only known once a
             * handshake names a server.  Saying so is better than checking
             * the literal text of the directive and reporting on a file
             * that does not exist.
             */
            ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                               "cert_expiry: a certificate given with "
                               "variables is not watched");
            continue;
        }

        certs = sscf->certificates->elts;

        for (j = 0; j < sscf->certificates->nelts; j++) {

            full = certs[j];

            if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
                return NGX_ERROR;
            }

            seen = 0;
            file = cemcf->files->elts;

            for (k = 0; k < cemcf->files->nelts; k++) {
                if (file[k].len == full.len
                    && ngx_strncmp(file[k].data, full.data, full.len) == 0)
                {
                    seen = 1;
                    break;
                }
            }

            if (seen) {
                continue;
            }

            file = ngx_array_push(cemcf->files);
            if (file == NULL) {
                return NGX_ERROR;
            }

            *file = full;
        }
    }

    ngx_http_cert_expiry_files = cemcf->files;
    ngx_http_cert_expiry_warn = cemcf->warn;

    return NGX_OK;
}
