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
  (cstruct)
  (checksum-fn))

(defparameter *udp-header*
  (make-header
   :type :udp
   :fields (list (make-hfield :name 'sport :bits 16)
                 (make-hfield :name 'dport :bits 16)
                 (make-hfield :name 'len   :bits 16)
                 (make-hfield :name 'checksum :bits 16))
   :cstruct (cffi:defcstruct udp-header
              (sport :uint16)
              (dport :uint16)
              (len   :uint16)
              (checksum :uint16))
   :checksum-fn #'udp-checksum))

(defun udp-checksum ())

(defparameter *tcp-header*
  (make-header
   :type :tcp
   :fields (list (make-hfield :name 'sport :bits 16)
                 (make-hfield :name 'dport :bits 16)
                 (make-hfield :name 'seqno :bits 32)
                 (make-hfield :name 'ackno :bits 32)
                 (make-hfield :name 'off+res+flags :bits 16)
                 (make-hfield :name 'window :bits 16)
                 (make-hfield :name 'checksum :bits 16)
                 (make-hfield :name 'urgent :bits 16)
                 (make-hfield :name 'opt+pad :bits 32))
   :cstruct (cffi:defcstruct tcp-header
              (sport :uint16)
              (dport :uint16)
              (seqno :uint32)
              (ackno :uint32)
              (off+res+flags :uint16)
              (window :uint16)
              (checksum :uint16)
              (urgent :uint16)
              (opt+pad :uint8))
   :checksum-fn #'tcp-checksum))

(defun tcp-checksum ())

(defparameter *icmp-header*
  (make-header
   :type :icmp
   :fields (list (make-hfield :name 'type :bits 8)
                 (make-hfield :name 'code :bits 8)
                 (make-hfield :name 'checksum :bits 16)
                 (make-hfield :name 'quench :bits 32))
   :cstruct (cffi:defcstruct icmp-header
              (type :uint8)
              (code :uint8)
              (checksum :uint16)
              (quench :uint32))
   :checksum-fn #'icmp-checksum))

(defun icmp-checksum ())

(defparameter *ip-header*
  (make-header
   :type :ip
   :fields (list (make-hfield :name 'ver-ihl :bits 8)
                 (make-hfield :name 'tos :bits 8)
                 (make-hfield :name 'len :bits 16)
                 (make-hfield :name 'id :bits 16)
                 (make-hfield :name 'flags+offset :bits 16)
                 (make-hfield :name 'ttl :bits 8)
                 (make-hfield :name 'protocol :bits 8)
                 (make-hfield :name 'checksum :bits 16)
                 (make-hfield :name 'saddr :bits 32)
                 (make-hfield :name 'daddr :bits 32)
                 (make-hfield :name 'opt+pad :bits 32))
   :cstruct (cffi:defcstruct ip-header
              (ver-ihl :uint8)
              (tos :uint8)
              (len :uint16)
              (id  :uint16)
              (flags+offset :uint16)
              (ttl :uint8)
              (protocol :uint8)
              (checksum :uint16)
              (saddr :uint32)
              (daddr :uint32)
              (opt+pad :uint32))
  :checksum-fn #'ip-checksum))

(defparameter *header-formats*
  (list *ip-header* *tcp-header* *udp-header* *icmp-header*))

(defun lookup-layout (type)
  (find type *header-formats* :key #'header-type))

(defun sizeof-header (type)
  (isys:sizeof (header-cstruct (lookup-layout type))))

(defun ip-checksum (p)
  (checksum-16 (header-halfwords :ip (particle-header :ip p))))

(defun header-halfwords (type data)
  (let (;;(data (particle-header type p :endian :big))
        (layout (lookup-layout type))
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
  (let ((data (loop repeat 12 collect (random #x10000))))
    (assert (zerop
             (checksum-16 (cons
                           (checksum-16 data)
                           data))))))
(defun +bench-checksum-16 ()
  ;; works *most* of the time. about one in #x10000 it'll fail.
  ;; not sure why, yet. 
  (time (loop repeat #x1000 do (+test-checksum-16))))
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

(defstruct (particle (:constructor make-particle (prng forms)))
  (fitness)
  (personal-best)
  (headers (loop for form in forms
                 collect (cons (header-type form)
                               (random-header form prng)))))

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
(defun write-ip-header (ip-header frame-len p)
  (let ((data (particle-header :ip p :endian :big)))
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
            daddr (elt data 9)+
            opt+pad (elt data 10)))))

(defun pack-frame (particle payload-size)
  (let* ((header-sizes (particle-header-sizes particle))
         (frame-size (reduce #'+ (cons payload-size header-sizes)))
         (cffi:with-foreign-object (frame :uint8 frame-size)
           (isys:bzero frame frame-size)


       
