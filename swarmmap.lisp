(in-package :swarmmap)

(defun rndround (f)
  (multiple-value-bind (int rem)
      (floor f)
    (if  (< (random 1.0) rem)
         (1+ int)
         int)))

(defun mt-round (mt f)
  (multiple-value-bind (int rem)
      (floor f)
    (if (< (mt-rnd mt 1000) (* rem 1000))
        (1+ int)
        int)))

(defun rounder (f)
  (round f))

(defstruct hfield
  (name nil)
  (bits 0 :type (unsigned-byte 8)))

(defstruct header
  (type)
  (fields '() :type cons)
  (cstruct))

(defun ip-checksum (p)
  (checksum-16 (header-halfwords :ip (particle-header :ip p))))

(defun %uint-keyword (bits)
  (intern (format nil "UINT~D" bits) :keyword))

(defmacro define-header-layout (symbol names-bits)
  (let ((n-b (if (symbolp names-bits)
                 (symbol-value names-bits)
                 names-bits))
        (struct (intern (format nil "~A-HEADER" symbol)))
        (param (intern (format nil "*~A-HEADER-LAYOUT*" symbol))))
    `(defparameter ,param
       (make-header
        :type ,symbol
        :fields (list ,@(loop for (name bits) in n-b
                              collect
                              (make-hfield :name name :bits bits)))
        :cstruct (cffi:defcstruct ,struct
                   ,@(loop for (name bits) in n-b
                           collect
                           (list name (%uint-keyword bits))))))))

(define-header-layout :udp ((sport 16)
                            (dport 16)
                            (len 16)
                            (checksum 16)))

(define-header-layout :tcp ((sport 16)
                            (dport 16)
                            (seqno 32)
                            (ackno 32)
                            (off+res+flags 16)
                            (window 16)
                            (checksum 16)
                            (urgent 16)
                            (opt+pad 16)))

(define-header-layout :icmp ((type 8)
                             (code 8)
                             (checksum 16)
                             (quench 32)))

(define-header-layout :ip ((ver-ihl 8)
                           (tos 8)
                           (len 16)
                           (id 16)
                           (flags+offset 16)
                           (ttl 8)
                           (protocol 8)
                           (checksum 16)
                           (saddr 32)
                           (daddr 32)
                           (opt+pad 32)))

(defparameter *header-formats*
  (list *ip-header-layout*
        *tcp-header-layout*
        *udp-header-layout*
        *icmp-header-layout*))

(defun lookup-layout (type)
  (find type *header-formats* :key #'header-type))

(defun sizeof-header (type)
  (isys:sizeof (header-cstruct (lookup-layout type))))

(defun header-halfwords (type data)
  (let ((layout (lookup-layout type))
        (halfwords ())
        (bit 8)
        (h 0))
    (loop for int in data
          for hfield in (header-fields layout)
          do
             (let* ((bits (hfield-bits hfield)))
               (cond ((= bits 32)
                      (push (ldb (byte 16 16) int) halfwords)
                      (push (ldb (byte 16  0) int) halfwords))
                     ((= bits 16)
                      (push int halfwords))
                     ((= bits 8)
                      (setf (ldb (byte 8 bit) h) int)
                      (when (zerop bit)
                        (push h halfwords))
                     (setf bit (mod (+ bit 8) 16)))
                     (t (print 'unexpected)))))
    (reverse halfwords))) ;; just to make debugging easier.
;; remove the reverse call later, as an optimization. won't make
;; a difference to the checksum. 

(defun checksum-16 (data)
  (let* ((sum (reduce #'+ data))
         (csum (ldb (byte 16 0) (+ sum (ldb (byte 1 16) sum)))))
    (ldb (byte 16 0) (lognot csum))))

(defun +test-checksum-16 ()
  (let ((data (loop repeat 12 collect (random #x10000)))
        (res  (zerop
               (checksum-16 (cons
                             (checksum-16 data)
                             data)))))
    (when (null res)
      (format t "+test-checksum-16 failed.
DATA: ~S
CHECKSUM: ~X
RECV-CHECKSUM: ~X~%"
              data (checksum-16 data)
              (checksum-16 (cons (checksum-16 data) data))))
    (assert res)))

(defun +bench-checksum-16 ()
  (time (loop repeat #x100000 do (+test-checksum-16))))

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

(defun random-header (header-format prng)
  (mapcar (lambda (x) (mt-rnd prng x))
          (mapcar (lambda (y) (expt 2 (hfield-bits y)))
                  (header-fields header-format))))

(defstruct (particle (:constructor make-particle (prng layouts)))
  (fitness)
  (personal-best)
  (headers (loop for layout in layouts
                 collect (cons (header-type layout)
                               (random-header layout prng)))))

(defun particle-header (hdr p &key (endian :big))
  (labels ((b (x hf)
             (case (hfield-bits hf)
               ((32) (swap-bytes::htonl (rounder x)))
               ((16) (swap-bytes::htons (rounder x)))
               ((8) (rounder x))))
           (f (x hf)
             (if (eq endian :big)
                 (b x hf)
                 (rounder x))))
    (mapcar #'f
            (cdr (assoc hdr (particle-headers p)))
            (header-fields (lookup-layout hdr)))))


(defun particle-header-sizes (p)
  (mapcar #'sizeof-header
          (mapcar #'car (particle-headers p))))

(defun particle-header-size (p)
  (reduce #'+ (particle-header-sizes p)))

;; not sure if i need these anymore
(defun little-endian-bytes (int width)
  (if (<= width 0) '()
      (cons (ldb (byte 8 0) int)
	    (little-endian-bytes (ash int -8) (- width 8)))))

(defun big-endian-bytes (int width)
  (reverse (little-endian-bytes int width)))
;;




;; TODO: This could probably be tidied up with some nice macros
(defun write-ip-header (ip-header p)
  (let ((data (particle-header :ip p :endian :big))
        (frame-len (particle-header-size p)))
    ;; no first build alist of sym-val pairs, mapping over ip-symbols
    ;; then calc checksum using it
    (cffi:with-foreign-slots ((ver-ihl
                               tos
                               len
                               id
                               flags+offset
                               ttl
                               protocol
                               checksum
                               saddr
                               daddr
                               opt+pad)
                              ip-header (:struct ip-header))
      (setf ver-ihl (elt data 0)
            tos (elt data 1)
            len frame-len ;; should calc this? or evolve it?
            id (elt data 3)
            flags+offset (elt data 4)
            ttl (elt data 5)
            protocol (elt data 6)
            checksum (checksum-16 (header-halfwords :ip data))
            saddr (elt data 8)
            daddr (elt data 9)
            opt+pad (elt data 10)))))

(defmacro define-header-writer (layout)
  (let* ((layout-struct (symbol-value layout))
         (name (intern (format nil "~A-HEADER-WRITER"
                               (header-type layout-struct))))
         (field-names
          (mapcar #'hfield-name
                  (header-fields layout-struct)))
        (htype (header-type layout-struct))
        (hcstruct (header-cstruct layout-struct)))
    `(defun ,name (buffer particle)
       (let ((data (particle-header ,htype
                                    particle
                                    :endian :big)))
         (cffi:with-foreign-slots (,field-names
                                   buffer ,hcstruct)
         ,@(loop for i from 0
                 for slot in field-names
                 collect
                 `(setf ,slot (elt data ,i)))))
       buffer)))

(define-header-writer *ip-header-layout*)
(define-header-writer *tcp-header-layout*)
(define-header-writer *udp-header-layout*)
(define-header-writer *icmp-header-layout*)

(defun ~test-write-ip-header (&optional (seed 99))
  (let* ((rng (make-mt seed))
         (p (make-particle rng (list *ip-header*)))
         (hsize (particle-header-size p)))
    (cffi:with-foreign-pointer (frame hsize)
      (isys:bzero frame hsize)
      (let* ((ip-header frame))
        (format t "IP HEADER: ~S~%" (particle-header :ip p))
        (write-ip-header ip-header p)
        (let ((hdr (loop for i below hsize collect
                                           (mem-aref frame :uint8 i))))
          (format t "PACKED:    ~S~%" hdr))))))

;(defun pack-frame (particle payload-size)
;  (let* ((header-sizes (particle-header-sizes particle))
;         (frame-size (reduce #'+ (cons payload-size header-sizes)))
;         (cffi:with-foreign-object (frame :uint8 frame-size)
;           (isys:bzero frame frame-size);
;
;))))
       
