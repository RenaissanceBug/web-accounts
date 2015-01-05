#lang racket

(provide start-web-auth-logger
         log-web-auth-error
         log-web-auth-warning
         log-web-auth-debug)

(define web-auth-log-file
  (make-parameter (build-path (current-directory) "web-auth.log")))

(define-logger web-auth)

(define (start-web-auth-logger [debug? #f])
  (define web-auth-receiver
    (make-log-receiver web-auth (if debug? 'debug 'warning) #f))
  (define op (open-output-file web-auth-log-file #:exists 'append))
  (void (thread
          (lambda ()
            (let loop ()
              (match (sync web-auth-receiver)
                [(vector event-level event-message event-value name)
                 (fprintf (format op "[~a] ~a\n" event-level event-message))
                 (loop)]))))))

(define (log-web-auth-event level message . vs)
  (log-message web-auth level
               (if (empty? vs) message (apply format (cons message vs)))
               #f))

(define (log-web-auth-error message . vs)
  (apply log-web-auth-event `(error ,message ,@vs)))

(define (log-web-auth-warning message . vs)
  (apply log-web-auth-event `(warning ,message ,@vs)))

(define (log-web-auth-debug message . vs)
  (apply log-web-auth-event `(debug ,message ,@vs)))
