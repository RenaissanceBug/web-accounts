#lang racket

(provide start-web-auth-logger
         web-auth-log-file
         log-web-auth-fatal
         log-web-auth-error
         log-web-auth-warning
         log-web-auth-info
         log-web-auth-debug)

(define web-auth-log-file
  (make-parameter (build-path (current-directory) "web-auth.log")))
(define web-auth-log-level (make-parameter 'info))
(define-logger web-auth)

(define (start-web-auth-logger)
  (define web-auth-receiver
    (make-log-receiver web-auth-logger (web-auth-log-level)))
  (define op (open-output-file (web-auth-log-file) #:exists 'append))
  (void (thread
          (lambda ()
            (let loop ()
              (match (sync web-auth-receiver)
                [(vector event-level event-message event-value name)
                 (fprintf op (format "[~a] ~a\n" event-level event-message))
                 (flush-output op)
                 (loop)]))))))

