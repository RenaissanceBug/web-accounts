#lang racket

(provide fresh-csrf-token
         fresh-csrf-token-/dev/random)

;; [Int+] -> Bytes
(define (fresh-csrf-token [len 20])
  (apply bytes
         (for/list ([i len]) (random 256))))

;; [Int+] -> Bytes
(define (fresh-csrf-token-/dev/random)
  (if (file-exists? "/dev/random")
      (with-input-from-file "/dev/random"
        (λ () (read-bytes)))
      (error 'fresh-csrf-token-/dev/random
             "no /dev/random on this system")))