(in-package :swarmmap)

(defun rndround (f)
  (declare (type (f float)))
  (multiple-value-bind (int rem)
      (floor f)
    (if (< (random 1.0) rem)
	(1+ int)
	int)))

(defun rounder (f)
  (round f))
;; first build lists of bit widths for each field, since we'll
;; need to have reference to those for packing purposes
;; then derive the max vals from those. 
;; 0                   1                   2                   3
;; 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |          Source Port          |       Destination Port        |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |                        Sequence Number                        |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |                    Acknowledgment Number                      |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |  Data |           |U|A|P|R|S|F|                               |
;; | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
;; |       |           |G|K|H|T|N|N|                               |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |           Checksum            |         Urgent Pointer        |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |                    Options                    |    Padding    |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;; |                             data                              |
;; +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
(defparameter *tcp-field-bits*
  '(16 ;; source port
    16 ;; destination port
    32 ;; sequence numbr
    32 ;; acknowledgement number
    04 ;; data offset
    06 ;; reserved
    06 ;; flags '(urg ack psh rst syn fin)
    16 ;; window
    16 ;; checksum
    16 ;; urgent pointer
    24 ;; options
    08)) ;; padding

(defparameter *tcp-header-indexes* ;; for debugging
  '((source-port . 0)
    (destination-port . 1)
    (sequence-number . 2)
    (acknowledgement-number . 3)
    (data-offset . 4)
    (reserved . 5)
    (flags . 6)
    (window . 7)
    (checksum . 8)
    (urgent-pointer . 9)
    (options . 10)
    (padding . 11)))

(defparameter *tcp-header-max-vals*
  (mapcar (lambda (x) (coerce (expt 2 x) 'float))
	  *tcp-field-bits*))

(defparameter *ip-field-bits*
  '(04 ;; version
    04 ;; IHL
    08 ;; TOS
    16 ;; total length
    16 ;; identification
    04 ;; flags
    12 ;; fragment offset
    08 ;; TTL
    08 ;; protocol
    16 ;; header checksum
    32 ;; source ip
    32 ;; destination ip
    32)) ;; options and padding

(defparameter *ip-header-indexes*
  '((version . 0)
    (ihl . 1)
    (tos . 2)
    (total-length . 3)
    (identification . 4)
    (flags . 5)
    (fragment-offset . 6)
    (ttl . 7)
    (protocol . 8)
    (header-checksum . 9)
    (source-ip . 10)
    (destination-ip . 11)
    (options-and-padding . 12)))

(defparameter *ip-header-max-vals*
  (mapcar (lambda (x) (coerce (expt 2 x) 'float)) *ip-field-bits*))

(defun header-bytespec-helper (name header)
  (let* ((indexes (if (eq header 'tcp)
		      *tcp-header-indexes*
		      *ip-header-indexes*))
	 (field-bits (if (eq header 'tcp)
			 *tcp-field-bits*
			 *ip-field-bits*))
	 (idx (cdr (assoc name indexes))))
    (byte (elt field-bits idx)
	  (reduce #'+ (subseq field-bits (1+ idx))))))

(defun tcp-header-bytespec (name)
  (header-bytespec-helper name 'tcp))

(defun ip-header-bytespec (name)
  (header-bytespec-helper name 'ip))

(defun get-field (header header-type name)
  (ldb (header-bytespec-helper name header-type) header))

(defstruct point
  (fitness)
  (personal-best)
  (ipfloats  (mapcar #'random *ip-header-max-vals*)
	     :type (cons float))
  (tcpfloats (mapcar #'random *tcp-header-max-vals*)
	     :type (cons float)))

(defun little-endian-bytes (int width)
  (if (<= width 0) '()
      (cons (ldb (byte 8 0) int)
	    (little-endian-bytes (ash int -8) (- width 8)))))

(defun big-endian-bytes (int width)
  (reverse (little-endian-bytes int width)))

(defun pack-ints-helper (ints widths ptr)
  (if (null ints) 0
      (dpb (car ints) (byte (car widths) ptr)
	   (pack-ints-helper (cdr ints)
			     (cdr widths)
			     (+ ptr (car widths))))))

(defun pack-ints (ints widths)
  (pack-ints-helper (reverse ints) (reverse widths) 0))

(defun pack-point (p)			  
  (let ((tcp (big-endian-bytes
	      (pack-ints
	       (mapcar #'rounder (point-tcpfloats p))
	       *tcp-field-bits*)
	      (* 32 6)))
	(ip (big-endian-bytes
	     (pack-ints
	      (mapcar #'rounder (point-ipfloats p))
	      *ip-field-bits*)
	     (* 32 6))))
    (list tcp ip)))
    
(defun point-tcp-field (name point)
  (elt (point-tcpfloats point)
       (cdr (assoc name *tcp-header-indexes*))))

(defun point-ip-field (name point)
  (elt (point-ipfloats point)
       (cdr (assoc name *ip-header-indexes*))))
