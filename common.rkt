#lang racket/base

(provide (all-defined-out))

;; An OAuth2Client is an oauth2-client struct:
(struct oauth2-client [id secret gdomain])
;; where...
;;       id : string, the Racket app's client ID
;;   secret : string, the Racket app's client secret
;;  gdomain : (Option String), the domain associated with your app if you want
;;            to restrict it to use only by members of a particular Google Apps
;;            domain; #f if not.

;; Exception subtype for failures to authenticate:
(struct exn:fail:authorization exn:fail ())

;;;; Error Responses ;;;;

(require web-server/http/response-structs
         xml)

(define (error-400 msg) ;; String -> Response
  (response/full
   400 #"Unauthorized"
   (current-seconds) TEXT/HTML-MIME-TYPE
   '()
   (list (string->bytes/utf-8
          (xexpr->string `(html (head (title "401"))
                                (body (h1 "Error 401; unauthenticated")
                                      (pre ,msg))))))))

(define (error-500 msg) ;; String -> Response
  (response/full
   500 #"Server Error"
   (current-seconds) TEXT/HTML-MIME-TYPE
   '()
   (list (string->bytes/utf-8
          (xexpr->string `(html (head (title "401"))
                                (body (h1 "Error 500")
                                      (pre ,msg))))))))
