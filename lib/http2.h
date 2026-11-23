#ifndef HEADER_CURL_HTTP2_H
#define HEADER_CURL_HTTP2_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

/* Classification of the closure of an HTTP/2 stream for the transfer that
 * owns it. It is derived from recorded stream state only by
 * `h2_eval_stream_close()`, see there for the exact boundaries. */
#define H2_CLOSE_COMPLETE 0 /* stream finished, nothing left to report */
#define H2_CLOSE_REFUSED  1 /* stream refused, may be retried elsewhere */
#define H2_CLOSE_IGNORED  2 /* reset after response, body was not wanted */
#define H2_CLOSE_ERROR    3 /* stream failed, see `.result` */

/* Effect of a stream closure on the reuse of its connection. A multiplexed
 * connection survives the failure of a single stream; only the case where
 * the server states it never processed the request makes libcurl abandon
 * the connection (the request is retried on a fresh one instead). */
#define H2_CONN_KEEP  0 /* connection stays usable for other streams */
#define H2_CONN_CLOSE 1 /* connection must not be reused */

struct h2_close_verdict {
  int action;      /* one of the H2_CLOSE_* values */
  int conn;        /* one of the H2_CONN_* values */
  CURLcode result; /* result to report for this action */
};

/* The state a stream closure evaluation is based upon. No pointer into
 * libcurl internals is needed, which makes the decision rule testable on its
 * own. All fields describe what has been observed for the stream so far. */
struct h2_close_state {
  uint32_t error;         /* HTTP/2 error code, 0 for a clean close */
  bool reset;             /* stream was reset, by peer or by us */
  bool resp_hds_complete; /* a final response header was fully received */
  bool bodystarted;       /* response body/trailers processing started */
  bool no_body;           /* the transfer is not interested in a body */
  bool has_data;          /* body bytes were already delivered to the user */
};

/* `h2_eval_stream_close()` maps a `struct h2_close_state` to its verdict.
 * It is declared as UNITTEST in http2.c, where the rule is documented. The
 * type and this comment stay outside the USE_NGHTTP2 guard so that the
 * prototype in generated `unitprotos.h` is well-formed in builds without
 * HTTP/2 support as well. */

#ifdef USE_NGHTTP2

#include <nghttp2/nghttp2.h>

/* value for MAX_CONCURRENT_STREAMS we use until we get an updated setting
   from the peer */
#define DEFAULT_MAX_CONCURRENT_STREAMS 100

/*
 * Store nghttp2 version info in this buffer.
 */
void Curl_http2_ver(char *p, size_t len);

#ifdef CURLVERBOSE
int Curl_nghttp2_fr_print(const nghttp2_frame *frame, char *buffer,
                          size_t blen);
#endif

CURLcode Curl_http2_request_upgrade(struct dynbuf *req,
                                    struct Curl_easy *data);

/* returns true if the HTTP/2 stream error was HTTP_1_1_REQUIRED */
bool Curl_h2_http_1_1_error(struct Curl_easy *data);

bool Curl_http2_may_switch_at(struct Curl_easy *data, struct Curl_cfilter *cf);

CURLcode Curl_http2_switch_at(struct Curl_easy *data, struct Curl_cfilter *cf);

CURLcode Curl_http2_upgrade(struct Curl_easy *data,
                            const char *mem, size_t nread);

void *Curl_nghttp2_malloc(size_t size, void *user_data);
void Curl_nghttp2_free(void *ptr, void *user_data);
void *Curl_nghttp2_calloc(size_t nmemb, size_t size, void *user_data);
void *Curl_nghttp2_realloc(void *ptr, size_t size, void *user_data);

extern struct Curl_cftype Curl_cft_nghttp2;

#else /* USE_NGHTTP2 */

#define Curl_http2_may_switch_at(a,b) FALSE

#define Curl_http2_request_upgrade(x, y)  CURLE_UNSUPPORTED_PROTOCOL
#define Curl_http2_switch_at(a,b)         CURLE_UNSUPPORTED_PROTOCOL
#define Curl_h2_http_1_1_error(x)         0
#endif

#endif /* HEADER_CURL_HTTP2_H */
