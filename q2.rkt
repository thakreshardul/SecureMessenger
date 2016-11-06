;; The first three lines of this file were inserted by DrRacket. They record metadata
;; about the language level of this file in a form that our tools can easily process.
#reader(lib "htdp-intermediate-lambda-reader.ss" "lang")((modname q2) (read-case-sensitive #t) (teachpacks ()) (htdp-settings #(#t constructor repeating-decimal #f #t none #f () #f)))
(require rackunit)
(require "extras.rkt")
(require "sets.rkt")

(provide make-pos
         make-neg
         make-clause
         is-null-derivable?)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; DATA DEFINITIONS:

;; A Variable is a Racket Symbol.

;; A ListOfVariable (LOV) is one of
;; -- empty
;; interp: A sequence of Variables with no elements
;; -- (cons Variable LOV)
;; interp: Represents a sequence of variables whose first element is an Variable
;;         and other elements are represented by LOV
;; TEMPLATE:
;; lov-fn : LOV -> ??
#;
(define (lov-fn lov)
  (cond
    [(empty? lov) ...]
    [else (... (first lov) (lov-fn (rest lov)))]))

(define-struct pos (var))
;; A Pos is a (make-pos Variable)
;; Interp: var is the positive literal
;; TEMPLATE:
;; pos-fn : Variable -> ??
#;
(define (pos-fn variable)
	(... (pos-var variable)))

(define-struct neg (var))
;; A Neg is a (make-neg Variable)
;; Interp: var is the negative literal
;; TEMPLATE:
;; neg-fn : Variable -> ??
#;
(define (neg-fn variable)
	(... (neg-var variable)))

;; A Literal is one of
;; -- (make-pos Variable)  Interp: a literal containing the variable
;; -- (make-neg Variable)  Interp: a literal containing the negation of
;;                                 the variable
;; TEMPLATE:
;; literal-fn : Literal -> ??
#;
(define (literal-fn literal)
  (cond
    [(pos? literal) (... (pos-fn literal))]
    [(neg? literal) (... (neg-fn literal))]))

;; A ListOfLiteral (LOL) is one of
;; -- empty
;; interp: A sequence of Literal with no elements
;; -- (cons Literal LOL)
;; interp: Represents a sequence of Literal whose first element is an Literal and 
;;         other elements are represented by LOL
;; TEMPLATE:
;; lol-fn : LOL -> ??
#;
(define (lol-fn lol)
  (cond
    [(empty? lol) ...]
    [else (... (literal-fn (first loexp)) (lol-fn (rest loexp)))]))

;; A SetOf<X> is a ListOf<X> WITH NO DUPLICATES

;; A Clause is a SetOfLiteral

;; A ListOfClause (LOC) is one of
;; -- empty
;; interp: A sequence of Clause with no elements
;; -- (cons Clause LOC)
;; interp: Represents a sequence of Clause whose first element is an Clause and 
;;         other elements are represented by LOC
;; TEMPLATE:
;; loc-fn : LOC -> ??
#;
(define (loc-fn loc)
  (cond
    [(empty? loc) ...]
    [else (... (first loc) (loc-fn (rest loc)))]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; CONSTANTS
(define UNIT 1)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; MISCELLANEOUS FUNCTIONS

;; make-clause : ListOfLiteral -> Clause
;; GIVEN: a list of literals, possibly with duplications
;; RETURNS: a clause containing exactly those literals
;;
(define (make-clause literals)
  (if (empty? literals)
      empty
      (set-cons (first literals) (make-clause (rest literals)))))
;; TESTS:
(begin-for-test
  (check-equal? (make-clause (list (make-pos 'a)
                                   (make-neg 'b)
                                   (make-neg 'c)))
                (make-clause (list (make-pos 'a)
                                   (make-neg 'b)
                                   (make-neg 'c)))
                "The clause should be correctly generated")
  (set-equal? (make-clause (list (make-pos 'a)
                                 (make-neg 'b)
                                 (make-neg 'c)
                                 (make-neg 'b)))
              (make-clause (list (make-pos 'a)
                                 (make-neg 'b)
                                 (make-neg 'c)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define TEST-CLAUSES (list (make-clause (list (make-pos 'a)
                                              (make-neg 'b)
                                              (make-neg 'c)))
                           (make-clause (list (make-neg 'a)
                                              (make-pos 'b)
                                              (make-neg 'c)))
                           (make-clause (list (make-neg 'a)
                                              (make-neg 'b)
                                              (make-pos 'c)))
                           (make-clause (list (make-neg 'a)
                                              (make-neg 'b)
                                              (make-pos 'a)))
                           (make-clause (list (make-pos 'c)
                                              (make-neg 'b)
                                              (make-neg 'c)))
                           (make-clause (list (make-pos 'c)
                                              (make-neg 'b)
                                              (make-neg 'c)
                                              (make-neg 'd)))))

(define NO-TAUTOLOGY-CLAUSES (list (make-clause (list (make-pos 'a)
                                                      (make-neg 'b)
                                                      (make-neg 'c)))
                                   (make-clause (list (make-neg 'a)
                                                      (make-pos 'b)
                                                      (make-neg 'c)))
                                   (make-clause (list (make-neg 'a)
                                                      (make-neg 'b)
                                                      (make-pos 'c)))))

(define LITERAL-DICTIONARY (list (make-pos 'a)
                                 (make-neg 'a)
                                 (make-pos 'b)
                                 (make-neg 'b)
                                 (make-pos 'c)
                                 (make-neg 'c)
                                 (make-neg 'd)))

(define SATISFIABLE (list (make-clause (list (make-pos 'p)))
                          (make-clause (list (make-neg 'p)))))

(define UNSATISFIABLE-CLAUSES (list (make-clause (list (make-pos 'a)
                                                       (make-neg 'b)
                                                       (make-pos 'c)))
                                    (make-clause (list (make-pos 'd)
                                                       (make-pos 'b)))
                                    (make-clause (list (make-neg 'a)
                                                       (make-pos 'c)))
                                    (make-clause (list (make-pos 'b)))
                                    (make-clause (list (make-neg 'c)))))

(define TEST (list (make-clause (list (make-neg 'p)
                                      (make-neg 'r)))
                   (make-clause (list (make-pos 'p)
                                      (make-pos 'q)))
                   (make-clause (list (make-pos 'r)
                                      (make-neg 'p)))
                   (make-clause (list (make-pos 'p)
                                      (make-neg 'q)))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; is-null-derivable? : ListOfClause -> Boolean
;; GIVEN: a list of clauses
;; RETURNS: true iff the empty clause is derivable from the given
;;          clauses using the rule of resolution as given above.
(define (is-null-derivable? clauses)
  (local ((define literals (process-literals clauses)))
    (not (satisfiable? (process clauses literals) literals))))
;; TEST:

;;
;;
;;
;;
(define (process clauses literals)
  (remove-superset-clauses (remove-tautologies (clauses-to-set clauses)) 
                           literals))
;;

;;
;;
;;
;;
(define (process-literals clauses)
  (literal-dictionary (remove-non-pair-literals (literal-list clauses))))
;;

;;
;;
;;
;;
(define (clauses-to-set clauses)
  (if (empty? clauses)
    empty
    (set-cons (first clauses) (clauses-to-set (rest clauses)))))
;;

;;
;;
;;
;;
(define (satisfiable? clauses literals)
  (cond
    [(empty? clauses) true]
    [(any-unit-clause? clauses) (unit-clause-satisfiable? clauses)]
    [else (local ((define reduced-literals (shrink-literals literals)))
                 (or (satisfiable? (simplify clauses (first literals)) reduced-literals)
                     (satisfiable? (simplify clauses (negative (first literals))) reduced-literals)))]))
;; TESTS:
(begin-for-test
  (check-true (satisfiable? (list (list (make-pos 'p1) (make-neg 'p2)) (list (make-neg 'p1) (make-pos 'p2)))
                            (process-literals (list (list (make-pos 'p1) (make-neg 'p2)) (list (make-neg 'p1) (make-pos 'p2)))))
              "The set is satisfiable"))

;;
;;
;;
;;
(define (any-unit-clause? clauses)
  (ormap (lambda (this-clause) (= UNIT (length this-clause))) clauses))
;;

;;
;;
;;
;;
(define (unit-clause-satisfiable? clauses)
  (cond
    [(complementary-unit-clauses? clauses) false]
    [else (empty? (simplify clauses (get-unit-clause clauses)))]))
;;

;;
;;
;;
;;
(define (complementary-unit-clauses? clauses)
  (cond 
    [(and (member? (get-unit-clause clauses) clauses)
          (member? (negative (get-unit-clause clauses)) clauses)) true]
    [(any-unit-clause? (rest clauses)) (complementary-unit-clauses? (rest clauses))]
    [else false]))
;;

;;
;;
;;
;;
(define (get-unit-clause clauses) 
  (foldl (;;
          ;;
          ;;
          ;;
          lambda (this-clause return-value) (if (= UNIT (length this-clause))
                                                 (first this-clause) 
                                                 return-value)) 
          empty 
          clauses))
;;

;;
;;
;;
;;
(define (shrink-literals literals)
  (remove (second literals) (remove (first literals) literals)))
;;

;;
;;
;;
;;
(define (simplify clauses literal)
  (cond
    [(empty? clauses) empty]
    [(member? literal (first clauses)) (simplify (rest clauses) literal)]
    [(member? (negative literal) (first clauses)) (list* (modify (first clauses) (negative literal)) (simplify (rest clauses) literal))]
    [else (list* (first clauses) (simplify (rest clauses) literal))]))
;;

;;
;;
;;
;;
(define (negative literal)
  (cond
    [(pos? literal) (make-neg (pos-var literal))]
    [(neg? literal) (make-pos (neg-var literal))]))
;;

;;
;;
;;
;;
(define (modify clause literal)
  (set-minus clause literal))
;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; UNIT PROPAGATION FUNCTION


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; THIS BLOCK REMOVES TAUTOLOGIES

;;
;;
;;
;;
(define (remove-tautologies clauses)
  (cond
    [(empty? clauses) clauses]
    [(is-tautology? (first clauses)) (remove (first clauses) (remove-tautologies (rest clauses)))]
    [else (cons (first clauses) (remove-tautologies (rest clauses)))]))
;; TESTS:
(begin-for-test
  (check-equal? (remove-tautologies TEST-CLAUSES)
                NO-TAUTOLOGY-CLAUSES
                "Tautologies are not properly removed"))

;;
;;
;;
;;
(define (is-tautology? clause)
  (cond
    [(empty? clause) false]
    [(neg-present? (first clause) (rest clause)) true]
    [else (is-tautology? (rest clause))]))
;;

;;
;;
;;
;;
(define (neg-present? literal lol)
  (if (pos? literal)
    (member? (make-neg (pos-var literal)) lol)
    (member? (make-pos (neg-var literal)) lol)))
;; TESTS:
(begin-for-test
  (check-equal? (neg-present? (make-neg 'a) (list
                                             (make-neg 'b)
                                             (make-pos 'a)))
                true
                "Complement is present in the same clause"))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; PURE LITERAL CLAUSE ELIMINATION

;;
;;
;;
;;
(define (literal-list clauses)
  (cond
    [(empty? clauses) empty]
    [else (set-union (first clauses) (literal-list (rest clauses)))]))
;; TESTS:
(begin-for-test
  (check-true (set-equal? (literal-list TEST-CLAUSES)
                          LITERAL-DICTIONARY)
              "A proper literal dictionary should be generated"))

;;
;;
;;
;;
(define (remove-non-pair-literals literals)
  (cond
    [(empty? (rest literals)) empty]
    [else (local ((define non-pair-list (remove-non-pair-literals (rest literals))))
            (if (neg-present? (first literals) (rest literals)) 
                (cons (first literals) non-pair-list)
                non-pair-list))]))
;; TESTS:
(begin-for-test
  (check-equal? (remove-non-pair-literals (list (make-pos 'a)
                                                (make-neg 'a)
                                                (make-pos 'b)
                                                (make-neg 'b)
                                                (make-pos 'd)
                                                (make-pos 'c)
                                                (make-neg 'c)))
                (list (make-pos 'a)
                      (make-pos 'b)
                      (make-pos 'c))
                "The list should not have non pair literals")
  (check-equal? (remove-non-pair-literals (literal-list TEST-CLAUSES))
                (list (make-pos 'b)
                      (make-neg 'a)
                      (make-pos 'c))
                "d should not be displayed"))

;;
;;
;;
;;
(define (literal-dictionary literals)
  (cond
    [(empty? literals) literals]
    [(pos? (first literals)) (list* (first literals) (make-neg (pos-var (first literals))) (literal-dictionary (rest literals)))]
    [(neg? (first literals)) (list* (first literals) (make-pos (neg-var (first literals))) (literal-dictionary (rest literals)))]))
;; TESTS:
(begin-for-test
  (check-equal? (literal-dictionary (list (make-pos 'b)
                            (make-neg 'a)
                            (make-pos 'c)))
                (list (make-pos 'b) (make-neg 'b) (make-neg 'a) (make-pos 'a) (make-pos 'c) (make-neg 'c))
                "Both positive and negative of the variable should be added in the dictionary"))

;;
;;
;;
;;
(define (remove-superset-clauses clauses literals)
  (cond
    [(empty? clauses) clauses]
    [(subset? (first clauses) literals) (cons (first clauses) (remove-superset-clauses (rest clauses) literals))]
    [else (remove-superset-clauses (rest clauses) literals)]))
;; TESTS:
(begin-for-test
  (check-equal? (remove-superset-clauses TEST-CLAUSES (list (make-pos 'a)
                                                 (make-pos 'b)
                                                 (make-pos 'c)
                                                 (make-neg 'a)
                                                 (make-neg 'b)
                                                 (make-neg 'c)))
                (list
 (list (make-pos 'a) (make-neg 'b) (make-neg 'c))
 (list (make-neg 'a) (make-pos 'b) (make-neg 'c))
 (list (make-neg 'a) (make-neg 'b) (make-pos 'c))
 (list (make-neg 'a) (make-neg 'b) (make-pos 'a))
 (list (make-pos 'c) (make-neg 'b) (make-neg 'c)))
                "All supersets must be removed"))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Note: The original version of this benchmark defined a function
;;; that didn't satisfy its contract.  That function was not needed
;;; by the benchmark and has been removed.  I have also added a call
;;; to make-clause.

;;; make-stress-input-sat : NonNegInt -> ListOfClause
;;; GIVEN: an integer n
;;; RETURNS: a satisfiable set of clauses of length n
;;; EXAMPLES:
;;;     (make-stress-input-sat 0) => empty
;;;     (make-stress-input-sat 3)
;;;  => (list (make-clause (list (make-pos 'p1)
;;;                              (make-neg 'p2)
;;;                              (make-neg 'p3)))
;;;           (make-clause (list (make-neg 'p1)
;;;                              (make-pos 'p2)
;;;                              (make-neg 'p3)))
;;;           (make-clause (list (make-neg 'p1)
;;;                              (make-neg 'p2)
;;;                              (make-pos 'p3))))

(define (make-stress-input-sat n)
  (local ((define (reverse-iota k)
            (if (= k 0)
                empty
                (cons k (reverse-iota (- k 1)))))
          (define (iota k)
            (reverse (reverse-iota k))))
    (let* ((nums (iota n))
           (syms (map (lambda (k)
                        (string->symbol (string-append "p"
                                                       (number->string k))))
                      nums)))
      (map (lambda (k)
             (make-clause   ; see note above
              (map (lambda (i)
                     ((if (= i k) make-pos make-neg)
                      (list-ref syms (- i 1))))
                   nums)))
           nums))))
;;; make-stress-input-unsat : PosInt -> ListOfClause
;;; GIVEN: an integer n
;;; RETURNS: an unsatisfiable set of clauses of length 2n

(define (make-stress-input-unsat n)
  (local ((define (reverse-iota k)
            (if (= k 0)
                empty
                (cons k (reverse-iota (- k 1)))))
          (define (iota k)
            (reverse (reverse-iota k))))
    (let* ((nums (iota n))
           (syms (map (lambda (k)
                        (string->symbol (string-append "p"
                                                       (number->string k))))
                      nums)))
      (cons (make-clause (list (make-neg (first syms))))
            (append
             (map (lambda (sym)
                    (make-clause (list (make-pos sym))))
                  (rest syms))
             (map (lambda (k)
                    (make-clause
                     (map (lambda (i)
                            ((if (= i k) make-pos make-neg)
                             (list-ref syms (- i 1))))
                          nums)))
                  nums))))))

;;; stress-benchmark2 : NonNegInt -> Boolean
;;; GIVEN: a non-negative integer n
;;; RETURNS: false
;;; EFFECT: reports how many milliseconds it takes to determine
;;;     (make-stress-input-sat n) is satisfiable

(define (stress-benchmark2 n)
  (time (is-null-derivable? (make-stress-input-unsat n))))
(stress-benchmark2 100)
(time (is-null-derivable? TEST))