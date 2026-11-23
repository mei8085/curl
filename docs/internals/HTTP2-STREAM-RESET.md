<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HTTP/2 stream reset and connection reuse

This note describes how libcurl turns the end of an HTTP/2 stream into a
result for the transfer that owns it, and what that means for the reuse of the
underlying connection. It documents `h2_eval_stream_close()` in `lib/http2.c`,
which is the single place the decision is made, and how its result is applied.

## The decision input

The verdict is computed from a `struct h2_close_state` (see `lib/http2.h`):

| field               | meaning                                                |
|---------------------|--------------------------------------------------------|
| `error`             | HTTP/2 error code of the close, 0 for a clean close    |
| `reset`             | the stream was reset, by the peer or by us             |
| `resp_hds_complete` | a complete, final response header was received         |
| `bodystarted`       | response body/trailer processing has started           |
| `no_body`           | the transfer does not want a response body             |
| `has_data`          | response body bytes were already handed to the user    |

The two structs are plain data; there is no pointer into libcurl internals in
them. That keeps the rule pure and makes it exercisable on its own (unit test
`3308`).

## The rule, in evaluation order

The first matching case wins:

1. **not reset, body started** -> `H2_CLOSE_COMPLETE`, `CURLE_OK`.
   The stream ended normally after the response had begun, existing response
   trailers, if any, are then delivered.
2. **not reset, body never started** -> `H2_CLOSE_ERROR`, `CURLE_HTTP2_STREAM`.
   The stream was closed cleanly but before a complete response header, so no
   response can be produced.
3. **reset, `error == NGHTTP2_REFUSED_STREAM`** -> `H2_CLOSE_REFUSED`,
   `CURLE_RECV_ERROR`, connection is marked for closing. The server states it
   did not process the request; the transfer is retried on a new connection.
   Whether the retry actually happens is up to `Curl_retry_request()`, which
   only does so when no response bytes were received yet.
4. **reset, response header complete and `no_body`** -> `H2_CLOSE_IGNORED`,
   `CURLE_OK`. Not reading a body (`HEAD`, or a body nobody wants) makes the
   server reset the stream; that is not an error.
5. **any other reset** -> `H2_CLOSE_ERROR`. With a non-zero `error` this is
   `CURLE_HTTP2_STREAM`; with `error == 0` it is `CURLE_PARTIAL_FILE` when body
   bytes were delivered and `CURLE_HTTP2` when none were.

Cases 1, 2, 4 and 5 all keep the connection. Only case 3 closes it. In
particular, a plain stream failure (case 5) does not disturb other transfers
multiplexed on the same connection.

## Applying the verdict

`http2_handle_stream_close()` is the only caller. It evaluates the state once,
acts on the verdict (raise the error, set `data->req.refused_stream`, log the
ignore case, deliver trailers on `H2_CLOSE_COMPLETE`), marks the stream as
handled and memorizes the *exact* result in `stream->close_result`. Any later
call for the same stream returns that memoized result unchanged, so the same
closed stream observed by the send path, the receive path and the frame
callbacks always yields the same answer. The `connclose()` for `H2_CONN_CLOSE`
runs only after the stream is marked handled, so an early error return cannot
leave the connection state unset.

## Re-entry and abnormal input

- The verdict depends only on recorded stream state; calling it again with the
  same state yields the same verdict, and it never modifies its input.
- `h2_eval_stream_close(NULL)` is defined as the all-zero state (no reset, no
  body started), i.e. case 2.
- `h2_stream_scratch_cleanup()` releases the per-stream request/response
  scratch (send buffer, H1 request parser, response trailers) and is safe to
  call repeatedly on a partially built stream. It is used on the request
  submission failure path (before the request reached nghttp2) and when the
  transfer is done with the stream. It never touches `push_headers`, which are
  owned by the `CURLMOPT_PUSHFUNCTION` callback path.

## Boundaries that the unit test pins down

`tests/unit/unit3308.c` drives each row above and the following boundaries
explicitly:

- `REFUSED_STREAM` wins over the `no_body` and `has_data` fields: the retry
  decision is *not* made in the verdict.
- `H2_CLOSE_IGNORED` requires *both* `resp_hds_complete` and `no_body`; a reset
  before the headers, or with a body wanted, is an error.
- With `error == 0` and a reset, `has_data` selects between
  `CURLE_PARTIAL_FILE` and `CURLE_HTTP2`.
- A clean close without a started body is a stream error.
- Only `REFUSED_STREAM` maps to `H2_CONN_CLOSE`.
