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
#include "unitcheck.h"
#include "http2.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGHTTP2)

/* One table entry for h2_eval_stream_close(). `expect_action` is one of the
 * H2_CLOSE_* values, `expect_conn` one of the H2_CONN_* values. */
struct t3308_case {
  const char *name;
  bool reset;
  uint32_t error;
  bool resp_hds_complete;
  bool bodystarted;
  bool no_body;
  bool has_data;
  int expect_action;
  int expect_conn;
  CURLcode expect_result;
};

static void t3308_check(const struct t3308_case *c)
{
  struct h2_close_state state;
  struct h2_close_verdict v;

  memset(&state, 0, sizeof(state));
  state.reset = c->reset;
  state.error = c->error;
  state.resp_hds_complete = c->resp_hds_complete;
  state.bodystarted = c->bodystarted;
  state.no_body = c->no_body;
  state.has_data = c->has_data;

  v = h2_eval_stream_close(&state);
  fail_unless(v.action == c->expect_action,
              "unexpected action for a stream close");
  fail_unless(v.conn == c->expect_conn,
              "unexpected connection reuse outcome for a stream close");
  fail_unless(v.result == c->expect_result,
              "unexpected result for a stream close");
  if(unitfail)
    curl_mfprintf(stderr, "  case: %s\n", c->name);
}

#endif /* !CURL_DISABLE_HTTP && USE_NGHTTP2 */

static CURLcode test_unit3308(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGHTTP2)
  static const struct t3308_case cases[] = {
    /* clean close after the response body started: normal completion */
    { "clean close, body started", FALSE, 0, TRUE, TRUE, FALSE, TRUE,
      H2_CLOSE_COMPLETE, H2_CONN_KEEP, CURLE_OK },
    /* clean close before any response: cannot produce a response */
    { "clean close, no body", FALSE, 0, FALSE, FALSE, FALSE, FALSE,
      H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_HTTP2_STREAM },
    /* refused stream: retryable on a fresh connection */
    { "refused stream", TRUE, NGHTTP2_REFUSED_STREAM, FALSE, FALSE, FALSE,
      FALSE, H2_CLOSE_REFUSED, H2_CONN_CLOSE, CURLE_RECV_ERROR },
    /* a refused stream stays retryable even if some bytes arrived */
    { "refused stream, with data", TRUE, NGHTTP2_REFUSED_STREAM, TRUE, TRUE,
      FALSE, TRUE, H2_CLOSE_REFUSED, H2_CONN_CLOSE, CURLE_RECV_ERROR },
    /* refusals ignore the no_body flag, the server did not process it */
    { "refused stream, no body", TRUE, NGHTTP2_REFUSED_STREAM, TRUE, TRUE,
      TRUE, FALSE, H2_CLOSE_REFUSED, H2_CONN_CLOSE, CURLE_RECV_ERROR },
    /* reset after headers we do not need a body for: ignored */
    { "reset, no body wanted", TRUE, NGHTTP2_INTERNAL_ERROR, TRUE, TRUE,
      TRUE, FALSE, H2_CLOSE_IGNORED, H2_CONN_KEEP, CURLE_OK },
    /* ... but only when a final response header is complete */
    { "reset, no body wanted, no hds", TRUE, NGHTTP2_INTERNAL_ERROR, FALSE,
      TRUE, TRUE, FALSE, H2_CLOSE_ERROR, H2_CONN_KEEP,
      CURLE_HTTP2_STREAM },
    /* ... and only when a body is not wanted at all */
    { "reset, body wanted", TRUE, NGHTTP2_INTERNAL_ERROR, TRUE, TRUE,
      FALSE, TRUE, H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_HTTP2_STREAM },
    /* error code present: CURLE_HTTP2_STREAM, connection kept */
    { "reset with error", TRUE, NGHTTP2_CANCEL, TRUE, TRUE, FALSE, TRUE,
      H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_HTTP2_STREAM },
    /* no error code, some data: partial file */
    { "reset, no code, with data", TRUE, 0, TRUE, TRUE, FALSE, TRUE,
      H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_PARTIAL_FILE },
    /* no error code, no data: total failure */
    { "reset, no code, no data", TRUE, 0, TRUE, TRUE, FALSE, FALSE,
      H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_HTTP2 },
    /* pure input: everything zero */
    { "reset only", TRUE, 0, FALSE, FALSE, FALSE, FALSE,
      H2_CLOSE_ERROR, H2_CONN_KEEP, CURLE_HTTP2 },
  };
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(cases); ++i)
    t3308_check(&cases[i]);

  /* A NULL state is specified to behave like an all-zero state. */
  {
    struct h2_close_verdict v = h2_eval_stream_close(NULL);
    fail_unless(v.action == H2_CLOSE_ERROR, "NULL state is an error");
    fail_unless(v.conn == H2_CONN_KEEP, "NULL state keeps the connection");
    fail_unless(v.result == CURLE_HTTP2_STREAM,
                "NULL state reports a stream error");
  }

  /* The verdict is a pure function of its input: repeating the call on
   * unchanged input yields the identical verdict, and a re-entrant call
   * (evaluating a second state from inside a probe) does not disturb it. */
  {
    struct h2_close_state a;
    struct h2_close_verdict v1, v2;

    memset(&a, 0, sizeof(a));
    a.reset = TRUE;
    a.error = NGHTTP2_REFUSED_STREAM;
    v1 = h2_eval_stream_close(&a);
    v2 = h2_eval_stream_close(&a);
    fail_unless(v1.action == v2.action, "verdict action is stable");
    fail_unless(v1.conn == v2.conn, "verdict conn is stable");
    fail_unless(v1.result == v2.result, "verdict result is stable");
    /* the input must not have been modified */
    fail_unless(a.reset && (a.error == NGHTTP2_REFUSED_STREAM),
                "verdict must not modify its input");
  }
#endif /* !CURL_DISABLE_HTTP && USE_NGHTTP2 */

  UNITTEST_END_SIMPLE
}
