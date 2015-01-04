#lang racket
(require net/http-client json)

(provide endpoints exn:fail:oauth-discovery
         end-keys end-key?)

(struct exn:fail:oauth-discovery exn:fail [])

;; Google's source for looking up the URIs for its OAuth2 endpoints:
(define discovery-host "accounts.google.com")
(define discovery-URL
  "https://accounts.google.com/.well-known/openid-configuration")

;; File in which to save the lookup:
(define cache-file "google-oauth-endpoints.json")

;; Most of the following keys in the JSON data are provided at Google's
;; discovery endpoint; we add expiration_date, which maps to the date
;; (as seconds since the epoch) at which the cache expires.
(define end-keys '(expiration_date
                   issuer authorization_endpoint token_endpoint
                          userinfo_endpoint revocation_endpoint
                          jwks_uri
                          response_types_supported
                          subject_types_supported
                          id_token_alg_values_supported
                          token_endpoint_auth_methods_supported))
;; For authentication purposes the _endpoint keys are the ones of interest.

;; Any -> Boolean
(define (end-key? x) (and (symbol? x) (memq x end-keys) #t))

;; [Boolean] [Path-String] -> (Hasheqof EndKey JSExpr)
;; Look up Google's OAuth endpoints, producing a hash that contains all
;; the authentication endpoints (and additional data from the discovery doc).
;; Caches (ands reads from a cache) if use-cache? is #t.
(define (endpoints [use-cache? #t] [cache-dir (current-directory)])
  (define cache (build-path cache-dir cache-file))
  (define (still-valid? data) ;; JSExpr -> 
    (< (current-seconds) (hash-ref data 'expiration_date 0)))
  (define (maybe-write-cache! jsx)
    (when (hash-ref jsx 'may-cache?)
      (call-with-atomic-output-file cache
        (λ (out path) (write-json jsx out)))
      jsx))
  
  (if use-cache?
      (if (file-exists? cache)
          (let ([cached (with-input-from-file cache read-json)])
            (if (still-valid? cached)
                cached
                (with-handlers ([exn:fail?
                                 ; Use cached version if we couldn't reach Google
                                 (λ (e) cached)])
                  (maybe-write-cache! (discover-endpoints)))))
          (maybe-write-cache! (discover-endpoints)))
      (discover-endpoints)))


;; discover-endpoints : -> (Hasheqof EndKey JSExpr)
;; Look up Google's OAuth endpoints. May add fields to describe cache behavior,
;; but performs no caching.
(define (discover-endpoints)
  (define (fail-with msg)
    (raise (exn:fail:oauth-discovery msg (current-continuation-marks))))
  (define-values (status headers ip)
    (http-sendrecv discovery-host discovery-URL #:ssl? #t))
  (unless (regexp-match? #"200" status) (fail-with (format "status: ~a" status)))
  (define jsx (read-json ip))
  (unless (hash-eq? jsx) (fail-with (format "malformed response: ~a" jsx)))
  (add-cache-headers headers jsx))

;; (Listof Bytes) JSExpr -> JSExpr
;; This fn adds 1-2 fields (may-cache? and possibly expiration_date) to the
;; given JSExpr if a Cache-Control header is present in headers.
(define (add-cache-headers headers jsx)
  (define cc (headers-ref headers #"Cache-Control"))
  (displayln cc)
  (if cc
      (let ([ccval (bytes->string/utf-8 cc)])
        (define now (current-seconds))
        (define options (string-split ccval #px"\\s*,\\s*"))
        (define may-cache? (and (member "public" options) #t))
        (define exp-date
          (for/or ([s options])
            (define max-age-s (regexp-match #rx"(?i:max-age=([0-9]+))" s))
            (and max-age-s (+ now (string->number (cadr max-age-s))))))
        
        (define jsx2 (hash-set jsx 'may-cache? may-cache?))
        ;; Set exp date, either as given or safely far in the future:
        (if may-cache?
            (hash-set jsx2 'expiration_date (if exp-date exp-date (* now 2)))
            jsx2))
      (hash-set jsx 'may-cache? #f)))

;; (Listof Bytes) Bytes -> (Option Bytes)
;; Fetches the value associated with the given key if it occurs in headers;
;; otherwise, produces #f.
(define (headers-ref headers key)
  (for/or ([hdr headers])
    (define hkey
      (cond [(regexp-match #px"^\\s*(\\S+):" hdr)
             => (compose string-downcase bytes->string/utf-8 cadr)]
            [else #f]))
    (and (string=? hkey (string-downcase (bytes->string/utf-8 key)))
         (cadr (regexp-match #px":\\s*(\\w.*)\\s*$" hdr)))))

(module+ test
  (require rackunit)
  (define sample-status #"HTTP/1.1 200 OK")
  (define sample-headers '(#"Expires: Sat, 10 Jan 2015 22:16:13 GMT"
                           #"Date: Sat, 03 Jan 2015 22:16:13 GMT"
                           #"Cache-Control: public, max-age=604800"
                           #"Last-Modified: Fri, 05 Dec 2014 04:03:03 GMT"
                           #"Content-Type: application/json"
                           #"Content-Length: 712"
                           #"X-Content-Type-Options: nosniff"
                           #"X-XSS-Protection: 1; mode=block"
                           #"Server: GSE"
                           #"Alternate-Protocol: 443:quic,p=0.02"
                           #"Connection: close"))
  
  (check-equal? (headers-ref sample-headers #"Expires")
                #"Sat, 10 Jan 2015 22:16:13 GMT")
  (check-equal? (headers-ref sample-headers #"connection")
                #"close")
  
  (define sample-discovery-jsx
    '#hasheq((issuer . "accounts.google.com")
             (authorization_endpoint
              . "https://accounts.google.com/o/oauth2/auth")
             (token_endpoint
              . "https://www.googleapis.com/oauth2/v3/token")
             (userinfo_endpoint
              . "https://www.googleapis.com/plus/v1/people/me/openIdConnect")
             (revocation_endpoint . "https://accounts.google.com/o/oauth2/revoke")
             (jwks_uri . "https://www.googleapis.com/oauth2/v2/certs")
             (response_types_supported . ("code"
                                          "token"
                                          "id_token"
                                          "code token"
                                          "code id_token"
                                          "token id_token"
                                          "code token id_token"
                                          "none"))
             (subject_types_supported . ("public"))
             (id_token_alg_values_supported . ("RS256"))
             (token_endpoint_auth_methods_supported . ("client_secret_post"))))
  
  (define ext-jsx (add-cache-headers sample-headers sample-discovery-jsx))
  (check-true (hash-ref ext-jsx 'may-cache?)
              "discover-endpoints setting may-cache? based on `public'")
  (check-equal? (hash-ref ext-jsx 'expiration_date)
                (+ (current-seconds) 604800)
                "discover-endpoints setting expiration_date")
  )