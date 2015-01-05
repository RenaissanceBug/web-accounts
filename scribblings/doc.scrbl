#lang scribble/manual

@(require (for-label racket json))

@title{web-accounts: Web User Account Management}

@author[(author+email "Jordan Johnson" "jmj@fellowhuman.com")]

@section{Common requirements: client data and exceptions}

@defmodule[web-accounts/common]

@defstruct*[(exn:fail:authorization exn:fail) ()]

Signals there was a problem in the authentication/authorization process.
This shouldn't propagate out of the library to client code.

@defstruct*[oauth2-client ([id string?]
                           [secret string?]
                           [gdomain (or/c string? #f)])]

Representation of a client web app's credentials. @racket[gdomain] is specific
to Google: If you have a particular Google Apps domain associated with your
application, setting @racket[gdomain] to that domain will restrict login to
members of that domain. Otherwise, @racket[gdomain] should be @racket{#f}.

@defproc[(error-400 [msg string?]) response?]{
  Creates a response of type @code{text/html} that indicates a 400 error
  has occurred.
}

@defproc[(error-500 [msg string?]) response?]{
  Creates a response of type @code{text/html} that indicates a 500 error
  has occurred.
}

@section{Logging}

@defmodule[web-accounts/auth-log]

Defines a @tech["logger" #:doc '(lib "scribblings/reference/reference.scrbl")]
that stores messages to a file. Messages of level @exec{'info} are generated when
users log in and out, and various @exec{'debug} and @exec{'error} messages may be
generated during the process of logging in.

@defparam[web-auth-log-file path path-string?
          #:value (build-path (current-directory) "web-auth.log")]{
  Specifies where to save the log.
}

@defparam[web-auth-log-level level log-level?
          #:value 'info]{
  Specifies the lowest level of messages to listen for in the auth log.
  Set this before calling @racket[start-web-auth-logger].
}

@defproc[(start-web-auth-logger) void?]{
  Starts a @racket[receiver] for web authentication/authorization events.
}

@deftogether[(
@defform*[[(log-web-auth-fatal string-expr)
           (log-web-auth-fatal format-string-expr v ...)]]
@defform*[[(log-web-auth-error string-expr)
           (log-web-auth-error format-string-expr v ...)]]
@defform*[[(log-web-auth-warning string-expr)
           (log-web-auth-warning format-string-expr v ...)]]
@defform*[[(log-web-auth-info string-expr)
           (log-web-auth-info format-string-expr v ...)]]
@defform*[[(log-web-auth-debug string-expr)
           (log-web-auth-debug format-string-expr v ...)]]
)]{
  Functions for logging web-auth messages.
}

@; ----------------------------------------

@section{CSRF token generation}

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

@section{OpenID endpoint discovery: Google}

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


