#lang web-server

(require web-server/servlet-env
         web-server/http/redirect
         racket/serialize)

(provide (struct-out oauth2-client)
         ends login-handler
         callback)

(define TESTING #f)

;; Exception subtype for failures to authenticate:
(struct exn:fail:authorization exn:fail ())

;; An OAuth2Client is an oauth2-client struct:
(struct oauth2-client [id secret hd])
;; where...
;;       id : string, the Racket app's client ID
;;   secret : string, the Racket app's client secret
;;       hd : (Option String), the domain associated with your app if you want
;;            to restrict it to use only by members of a particular Google Apps
;;            domain; #f if not.

;; The Racket app's host, for purposes of building an authorization callback URI


(require "google/endpoints.rkt")

(define ends (endpoints))
(define auth-uri-string (hash-ref ends 'authorization_endpoint))
(define token-uri-string (hash-ref ends 'token_endpoint))

(define example-client
  (oauth2-client "woowoowoo.apps.googleusercontent.com"
                 "woowoosecretwoowoo@developer.gserviceaccount.com"
                 #f))


(require "csrf-token.rkt")
(define token (fresh-csrf-token))


(require net/uri-codec ;; alist->form-urlencoded
         net/url       ;; string->url
         file/sha1     ;; bytes->hex-string
         )

(define (user-auth-query me callback-url)
  (alist->form-urlencoded `((client_id     . ,(oauth2-client-id me))
                            (response_type . "code")
                            (scope         . "openid email")
                            (redirect_uri  . ,callback-url)
                            (state         . ,(bytes->hex-string token))
                            ,@(let ([hd (oauth2-client-hd me)])
                                (if hd `((hd . ,hd)) '())))))

(require "auth-log.rkt")

;; login-handler : OAuth2Client String -> Response
;; 1) Redirects the client to the provider's auth URI, with a local
;;    redirect URI for after the user authorizes access.
(define (login-handler client callback-url)
  (lambda (req)
    (when TESTING
      (printf "Sending user to Google\n\t(redirect_uri=~a)\n" callback-url))
    (redirect-to
      (format "~a?~a"
              auth-uri-string
              (user-auth-query client callback-url)))))

;; OAuth2Client String -> JSExpr
;; 2) Validates the client's request to the local redirect URI.
;; 3) Contacts the provider's server at its token URI, to obtain a token.
(define (callback client callback-url)
  (lambda (req/code)
    (define bindings (request-bindings/raw req/code))
    (define (maybe-get key)
      (match (bindings-assq key bindings)
        [(? binding:form? b)
         (bytes->string/utf-8 (binding:form-value b))]
        [_ #f]))

    ;; Validate user's redirected request:
    (define auth-error (maybe-get #"error"))
    (when auth-error (error-400 auth-error))

    (define state (maybe-get #"state"))
    (unless (equal? state (bytes->hex-string token))
      (error-400 "missing token"))

    (define code (maybe-get #"code")) ; auth code from Google
    (unless code (error-400 "missing authorization code"))

    (request-access-token client token-uri-string code callback-url))
  ;; TODO: Extract info from the ID token, check the user against our DB,
  ;; redirect to right page...
  )

(require net/http-client json openssl)

;; OAuth2Client String String String -> JSExpr
;; Connects to Google to request an access token verifying the user's identity.
;; Produces a JSExpr containing info about the user. XXX make more precise
(define (request-access-token client token-uri-string auth-code callback-url)
  (with-handlers ([exn:fail? (lambda (e)
                               (error-500
                                 (format "error in acquiring token: ~a"
                                         (exn-message e))))]
                  [exn:fail:authorization?
                    (lambda (e)
                      (error-500 (exn-message e)))])
    (define-values (status headers ip)
      (http-sendrecv (url-host (string->url token-uri-string))
                     token-uri-string
                     #:method #"POST"
                     #:ssl? (ssl-secure-client-context)
                     #:data
                     (alist->form-urlencoded
                       `((code          . ,auth-code)
                         (client_id     . ,(oauth2-client-id client))
                         (client_secret . ,(oauth2-client-secret client))
                         (redirect_uri  . ,callback-url)
                         (grant_type    . "authorization_code")))
                     #:headers
                     (list "Content-Type: application/x-www-form-urlencoded")))
    (unless (regexp-match? #rx"200" status)
      (raise (exn:fail:authorization
               (format
                 "Failed to obtain token from Google.\nStatus: ~a\nBody:\n~a"
                 status
                 (port->string ip))
               (current-continuation-marks))))

    (with-handlers ([exn:fail?
                      (lambda (e)
                        (error-401 "malformed access token from Google"))])
      (read-json ip))))

(require xml)
(define (error-400 msg) ;; String -> Response
  (response/full
   400 #"Unauthorized"
   (current-seconds) TEXT/HTML-MIME-TYPE
   empty
   (list (string->bytes/utf-8
          (xexpr->string `(html (head (title "401"))
                                (body (h1 "Error 401; unauthenticated")
                                      (pre ,msg))))))))

(define (error-500 msg) ;; String -> Response
  (response/full
   500 #"Server Error"
   (current-seconds) TEXT/HTML-MIME-TYPE
   empty
   (list (string->bytes/utf-8
          (xexpr->string `(html (head (title "401"))
                                (body (h1 "Error 500")
                                      (pre ,msg))))))))

#|
DONE:
0. retrieve the base URI from the Discovery document using the key
   authorization_endpoint. (Cache the Discovery document.)
1. Create an anti-forgery state token
2. Send an authentication request to Google
3. Confirm anti-forgery state token when callback request comes in

TODO:
4. Exchange code for access token and ID token
5. Obtain user information from the ID token
6. Authenticate the user
All this is described at:
  https://developers.google.com/accounts/docs/OpenIDConnect#getcredentials

Once we've tested all this, we'll need to get into setting up
  - new-user signup flow
  - behavior for authenticated users.
  - admin pages for managing users
|#

