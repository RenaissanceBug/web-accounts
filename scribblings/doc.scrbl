#lang scribble/manual

@(require (for-label racket json))

@title{web-accounts: Web User Account Management}

@author[(author+email "Jordan Johnson" "jmj@fellowhuman.com")]

@section{CSRF Token Generation}

@defmodule[web-accounts/csrf-token]

For generating random byte-strings for use as CSRF tokens.

@defproc[(fresh-csrf-token [len exact-positive-integer? 20])
         bytes?]{
  Produces a random token of length @exec{len}.
}

@defproc[(fresh-csrf-token-/dev/random [len exact-positive-integer? 20])
         bytes?]{
  Produces a random token of length @exec{len}, by reading from
  @exec{/dev/random}. If the system has no @exec{/dev/random},
  this function raises an error.
}

@section{OpenID Endpoint Discovery: Google}

@defmodule[web-accounts/google/endpoints]

A library for fetching Google's current OAuth2 endpoints, as specified in
@link["https://developers.google.com/accounts/docs/OpenIDConnect"]{Google's
developer docs}.

@defproc[(endpoints [use-cache? boolean? #t]
                    [cache-dir path-string? (current-directory)])
         (hash/c end-key? jsexpr?)]{
Look up Google's OAuth endpoints, producing a hash that contains all
the authentication endpoints (and additional data from the discovery doc).
Caches (ands reads from a cache) if @exec{use-cache?} is @racket{#t}.
}

@defthing[end-key (one-of/c '(issuer authorization_endpoint token_endpoint
                                     userinfo_endpoint revocation_endpoint
                                     jwks_uri
                                     response_types_supported
                                     subject_types_supported
                                     id_token_alg_values_supported
                                     token_endpoint_auth_methods_supported))]{
  A key that may be present in the JSExpr that describes Google's OAuth2
  endpoints and interface.
}

@defproc[(end-key? [x any/c]) boolean?]{
  Type predicate for end-key data.
}


