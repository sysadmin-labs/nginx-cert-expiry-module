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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


/* a hundred years, the fence against a notAfter that overflows a 32 bit time_t */
#define NGX_HTTP_CERT_EXPIRY_MAX_DAYS  36500


typedef struct {
    ngx_str_t     name;         /* the file, as the configuration names it */
    time_t        expires;      /* when it runs out, read in the master */
    ngx_uint_t    valid;        /* the file could be read */
} ngx_http_cert_expiry_cert_t;


typedef struct {
    ngx_array_t  *certs;        /* of ngx_http_cert_expiry_cert_t */
    ngx_msec_t    interval;     /* how often the check runs again */
    time_t        warn;         /* warn below this many seconds left */
} ngx_http_cert_expiry_main_conf_t;


static ngx_int_t ngx_http_cert_expiry_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cert_expiry_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_cert_expiry_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_cert_expiry_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_cert_expiry_postconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_cert_expiry_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_cert_expiry_init_process(ngx_cycle_t *cycle);
static void ngx_http_cert_expiry_exit_process(ngx_cycle_t *cycle);
static void ngx_http_cert_expiry_timer(ngx_event_t *ev);
static void ngx_http_cert_expiry_check(
    ngx_http_cert_expiry_main_conf_t *cemcf, ngx_log_t *log);
static time_t ngx_http_cert_expiry_days(int days, int seconds);


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
    ngx_http_cert_expiry_init_module,       /* init module */
    ngx_http_cert_expiry_init_process,      /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_cert_expiry_exit_process,      /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_event_t  ngx_http_cert_expiry_event;

/*
 * ngx_add_timer() and ngx_del_timer() read ev->data as an ngx_connection_t
 * to name a descriptor in their debug lines, so a timer without a
 * connection of its own needs one that can be read.  This is the same dummy
 * nginx uses for its cache manager.
 */
static ngx_connection_t  ngx_http_cert_expiry_dumb;


static ngx_str_t  ngx_http_cert_expiry_name =
    ngx_string("ssl_expiry_days");


/*
 * Days left on the certificate this connection was served with: the one
 * OpenSSL picked, not the first one configured.  The two differ on a server
 * carrying an RSA and an ECDSA certificate.
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
        ERR_clear_error();
        v->not_found = 1;
        return NGX_OK;
    }

    left = ngx_http_cert_expiry_days(days, seconds);

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
 * Days left, rounded towards the past.  ASN1_TIME_diff() hands back days
 * and seconds separately; dropping the seconds would report 0 for a
 * certificate that ran out an hour ago, which is the one number nobody may
 * confuse with "still valid".  A notAfter far enough out to overflow a 32
 * bit time_t is pinned at a hundred years.
 */
static time_t
ngx_http_cert_expiry_days(int days, int seconds)
{
    time_t  left;

    if (days > NGX_HTTP_CERT_EXPIRY_MAX_DAYS) {
        days = NGX_HTTP_CERT_EXPIRY_MAX_DAYS;

    } else if (days < -NGX_HTTP_CERT_EXPIRY_MAX_DAYS) {
        days = -NGX_HTTP_CERT_EXPIRY_MAX_DAYS;
    }

    left = (time_t) days * 86400 + seconds;

    if (left < 0 && left % 86400 != 0) {
        return left / 86400 - 1;
    }

    return left / 86400;
}


/*
 * When the certificate in this file runs out.  Read in the master, where
 * the configuration is read and the privileges are still those of the
 * process that started nginx: a worker runs as an unprivileged user and a
 * certificate on disk is commonly readable by root alone.
 */
static ngx_int_t
ngx_http_cert_expiry_read(ngx_str_t *file, time_t *expires, ngx_log_t *log)
{
    BIO        *bio;
    X509       *cert;
    int         days, seconds;
    ASN1_TIME  *notafter;

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        ERR_clear_error();
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: cannot open \"%V\"", file);
        return NGX_ERROR;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);

    if (cert == NULL) {
        ERR_clear_error();
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: \"%V\" holds no PEM certificate", file);
        return NGX_ERROR;
    }

    notafter = X509_getm_notAfter(cert);

    if (notafter == NULL || !ASN1_TIME_diff(&days, &seconds, NULL, notafter)) {
        ERR_clear_error();
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "cert_expiry: \"%V\" has no readable notAfter", file);
        X509_free(cert);
        return NGX_ERROR;
    }

    X509_free(cert);

    if (days > NGX_HTTP_CERT_EXPIRY_MAX_DAYS) {
        days = NGX_HTTP_CERT_EXPIRY_MAX_DAYS;
        seconds = 0;
    }

    *expires = ngx_time() + (time_t) days * 86400 + seconds;

    return NGX_OK;
}


static void
ngx_http_cert_expiry_check(ngx_http_cert_expiry_main_conf_t *cemcf,
    ngx_log_t *log)
{
    time_t                        left, ago;
    ngx_uint_t                    i;
    ngx_http_cert_expiry_cert_t  *cert;

    if (cemcf->certs == NULL) {
        return;
    }

    cert = cemcf->certs->elts;

    for (i = 0; i < cemcf->certs->nelts; i++) {

        if (!cert[i].valid) {
            continue;
        }

        left = cert[i].expires - ngx_time();

        if (left <= 0) {

            /* under a day counts as one, never as none */
            ago = -left / 86400;

            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "certificate \"%V\" expired %T days ago",
                          &cert[i].name, ago ? ago : 1);
            continue;
        }

        if (left <= cemcf->warn) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "certificate \"%V\" expires in %T days",
                          &cert[i].name, (time_t) (left / 86400));
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "certificate \"%V\" is good for %T more days",
                      &cert[i].name, (time_t) (left / 86400));
    }
}


static void
ngx_http_cert_expiry_timer(ngx_event_t *ev)
{
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    /*
     * From the cycle and not from a pointer kept across the reload: the
     * configuration this timer was armed for may be gone by now.
     */
    cemcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_cert_expiry_module);
    if (cemcf == NULL) {
        return;
    }

    ngx_http_cert_expiry_check(cemcf, ev->log);

    if (!ngx_exiting && !ngx_terminate && !ngx_quit) {
        ngx_add_timer(ev, cemcf->interval);
    }
}


/*
 * The master reads the dates; the worker only subtracts them from the
 * clock.  A certificate that was renewed on disk is read again when the
 * configuration is, which is also when nginx starts serving it.
 */
static ngx_int_t
ngx_http_cert_expiry_init_module(ngx_cycle_t *cycle)
{
    ngx_uint_t                         i;
    ngx_http_cert_expiry_cert_t       *cert;
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_cert_expiry_module);

    if (cemcf == NULL || cemcf->certs == NULL) {
        return NGX_OK;
    }

    cert = cemcf->certs->elts;

    for (i = 0; i < cemcf->certs->nelts; i++) {
        cert[i].valid = (ngx_http_cert_expiry_read(&cert[i].name,
                                                   &cert[i].expires,
                                                   cycle->log) == NGX_OK);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cert_expiry_init_process(ngx_cycle_t *cycle)
{
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_cert_expiry_module);

    if (cemcf == NULL || cemcf->certs == NULL || cemcf->certs->nelts == 0) {
        return NGX_OK;
    }

    /*
     * One worker reports: every worker writing the same line would say the
     * same thing once per worker.
     */
    if (ngx_process == NGX_PROCESS_WORKER && ngx_worker != 0) {
        return NGX_OK;
    }

    ngx_http_cert_expiry_check(cemcf, cycle->log);

    ngx_http_cert_expiry_dumb.fd = (ngx_socket_t) -1;

    ngx_http_cert_expiry_event.handler = ngx_http_cert_expiry_timer;
    ngx_http_cert_expiry_event.log = cycle->log;
    ngx_http_cert_expiry_event.data = &ngx_http_cert_expiry_dumb;
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

    /* 14d */
    ngx_conf_init_value(cemcf->warn, 14 * 86400);

    /* 12h */
    ngx_conf_init_msec_value(cemcf->interval, 12 * 60 * 60 * 1000);

    return NGX_CONF_OK;
}


/*
 * Collect every file named by an ssl_certificate, once.  The list is built
 * in the master, so a worker never walks the configuration for this.
 */
static ngx_int_t
ngx_http_cert_expiry_postconf(ngx_conf_t *cf)
{
    ngx_str_t                         *values, full;
    ngx_uint_t                         i, j, k, seen;
    ngx_http_ssl_srv_conf_t           *sscf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_cert_expiry_cert_t       *cert;
    ngx_http_cert_expiry_main_conf_t  *cemcf;

    cemcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_cert_expiry_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    cemcf->certs = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_http_cert_expiry_cert_t));
    if (cemcf->certs == NULL) {
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
             * The file name carries variables and is known only once a
             * handshake has named a server.  The literal text of the
             * directive names no file, so there is nothing to read here.
             */
            ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                               "cert_expiry: a certificate given with "
                               "variables is not watched");
            continue;
        }

        values = sscf->certificates->elts;

        for (j = 0; j < sscf->certificates->nelts; j++) {

            /*
             * nginx takes a certificate inline as well, "data:..." and
             * "engine:...".  Those name no file, so there is nothing here
             * to open and a date to read.
             */
            if (ngx_strncmp(values[j].data, "data:", 5) == 0
                || ngx_strncmp(values[j].data, "engine:", 7) == 0)
            {
                ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                                   "cert_expiry: a certificate that is not "
                                   "a file is not watched");
                continue;
            }

            full = values[j];

            if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
                return NGX_ERROR;
            }

            seen = 0;
            cert = cemcf->certs->elts;

            for (k = 0; k < cemcf->certs->nelts; k++) {
                if (cert[k].name.len == full.len
                    && ngx_strncmp(cert[k].name.data, full.data, full.len)
                       == 0)
                {
                    seen = 1;
                    break;
                }
            }

            if (seen) {
                continue;
            }

            cert = ngx_array_push(cemcf->certs);
            if (cert == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(cert, sizeof(ngx_http_cert_expiry_cert_t));
            cert->name = full;
        }
    }

    return NGX_OK;
}
