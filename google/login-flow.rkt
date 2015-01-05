#lang web-server

(require web-server/servlet-env
         web-server/http/redirect
         racket/serialize)

(provide (struct-out oauth2-client)
         ends login-handler
         callback)

(require "endpoints.rkt"
         "../common.rkt"
         "../auth-log.rkt")

(define ends (endpoints))
(define auth-uri-string (hash-ref ends 'authorization_endpoint))
(define token-uri-string (hash-ref ends 'token_endpoint))




(require "../csrf-token.rkt")
(define token (fresh-csrf-token))


(require net/uri-codec ;; alist->form-urlencoded
         net/url       ;; string->url
         file/sha1     ;; bytes->hex-string
         )

;; login-handler : OAuth2Client String -> Response
;; 1) Redirects the client to the provider's auth URI, with a local
;;    redirect URI for after the user authorizes access.
(define (login-handler client callback-url)
  (lambda (req)
    (log-debug "Sending user to redirect_uri=~a\n" callback-url)
    (redirect-to
      (format "~a?~a"
              auth-uri-string
              (alist->form-urlencoded
               `((client_id     . ,(oauth2-client-id client))
                 (response_type . "code")
                 (scope         . "openid email")
                 (redirect_uri  . ,callback-url)
                 (state         . ,(bytes->hex-string token))
                 ,@(let ([hd (oauth2-client-gdomain client)])
                     (if hd `((hd . ,hd)) '()))))))))

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
    (define state (maybe-get #"state"))
    (define code (maybe-get #"code")) ; auth code from Google
    (cond
      [auth-error
       (log-web-auth-error "error in user's 2nd request")
       (error-400 auth-error)]
      [(not (equal? state (bytes->hex-string token)))
       (log-web-auth-error "invalid state token ~a" state)
       (error-400 "missing token")]
      [(not code)
       (log-web-auth-error "missing authorization code in user's 2nd request")
       (error-400 "missing authorization code")]
      [else
       (log-web-auth-debug "received authentication code: ~a" code)
       (request-access-token client token-uri-string code callback-url)])))

(require net/http-client json openssl)

;; OAuth2Client String String String -> JSExpr
;; Connects to Google to request an access token verifying the user's identity.
;; Produces a JSExpr containing info about the user, of the form
;;  {access_token: String, id_token: JWT, expires_in: Int+, token_type: String}
(define (request-access-token client token-uri-string auth-code callback-url)
  (log-web-auth-debug "requesting access token from Google")
  (with-handlers ([exn:fail?
                   (lambda (e)
                     (define msg
                       (format "error in acquiring token: ~a" (exn-message e)))
                     (log-web-auth-error msg)
                     (error-500 msg))]
                  [exn:fail:authorization?
                    (lambda (e)
                      (log-web-auth-error (exn-message e))
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
    (log-web-auth-debug "received response (status: ~a) from Google" status)
    (unless (regexp-match? #rx"200" status)
      (raise (exn:fail:authorization
               (format
                 "Failed to obtain token from Google.\nStatus: ~a\nBody:\n~a"
                 status
                 (port->string ip))
               (current-continuation-marks))))

    (with-handlers ([exn:fail?
                      (lambda (e)
                        (define msg "malformed access token from Google")
                        (log-web-auth-error msg)
                        (error-400 msg))])
      (read-json ip))))



#|All this is described at:
  https://developers.google.com/accounts/docs/OpenIDConnect#getcredentials
|#

