;;; Copyright (c) 2017 William R. Felts III, All Rights Reserved
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;
;;;; cl-cognito.lisp

(in-package #:cl-cognito)

;;; "cl-cognito" goes here. Hacks and glory await!

;;;;
;;;; AWS Cognito Services
;;;;
;;;; Based on https://github.com/capless/warrant, in particular, aws_srp.py, with an
;;;; assist from https://gist.github.com/dbeattie71/44ea3a13145f185d303e620c299ab1c5.
;;;; The key to getting it to work with a client secret was in the answer by Ron Sijm in
;;;; https://stackoverflow.com/questions/37438879/resolve-unable-to-verify-secret-hash-for-client-in-amazon-cognito-userpools/
;;;; namely, by adding the user's email along with the secret hash.
;;;; 
;;;; This is a John Searle "Chinese Room" translation of the Python code.  That is, I translated it, but
;;;; I don't understand it. [1]  Partly because I don't have a lot of experience in crypto, partly because
;;;  the Amazon documention is sorely lacking.  To aid in the translation of the Python code, I did something
;;;; very non-Lispy -- I annotated certain variables/functions with type information. It's "Apps Hungarian"
;;;; that bears a striking resemblence to "Systems Hungarian".  But it's the only way I could keep track
;;;; of things without understanding what I was doing.  This notation isn't used consistently. "I am large,
;;;; I contain multitudes."
;;;; 
;;;; Variable naming conventions
;;;;   <name>      : (usually) an integer.  (Lisp doesn't care how big it is)
;;;;   <name>_s    : a string
;;;;   <name>_hs   : a string of hex digits, lower case
;;;;   <name>_phs  : a "padded" hex string
;;;;   <name>_b64s : a base64 string
;;;;   <name>_ba   : a "byte array", i.e. '(vector (unsigned-byte 8))
;;;;   <name>_js   : decoded JSON
;;;;
;;;; Functions use /<type>, e.g. (foo/js bar_ba)
;;;;
;;;; The code errors out if the "u" parameter is zero or the "a" parameter mod something is zero.
;;;; I suspect the code could generate another random number and try again, but the Python code
;;;; didn't do that. C'est la vie.
;;;;
;;;; I translated the Python code to use a more functional style. I wanted to be able to trace
;;;; what inputs were needed for what outputs and using class methods made what was going on
;;;; less obvious.
;;;;
;;;; ==========
;;;; [1] As an aside, this hopefully shows why Searle's argument is wrong, since on most days
;;;; I can pass a Turing test.
;;;;


;;;;
;;;; constants
;;;;
(defparameter *n* #xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff)

(defparameter *g* 2)

;;;;
;;;; general support routines
;;;;

;;; integer to lower-case hex string.
;;; Note: ~(...~) is the case conversion specifier
;;; [http://www.lispworks.com/documentation/HyperSpec/Body/22_cha.htm]
(defun integer-to-hex-string (n)
  (format nil "~(~x~)" n))

(defun hex-string-to-integer (s)
  (parse-integer s :radix 16))

(defun octets-to-string (octets)
  (babel:octets-to-string octets :encoding :utf-8))

(defun string-to-octets (string)
  (babel:string-to-octets string :encoding :utf-8))

(defun json-decode-octets/js (octets)
  (json:decode-json-from-string (octets-to-string octets)))

;;;;
;;;; dexador interface
;;;;
(defparameter *dex-keep-alive* nil)
(defparameter *dex-verbose* nil)

;;;
;;; returns:
;;;  result code nil => in the success case
;;;  nil code response => in the error case
;;;
(defun post (url_s headers_s content_s)
  (handler-case
      (multiple-value-bind (result code)
	  (dex:post url_s
		    :headers headers_s
		    :content content_s
		    :keep-alive *dex-keep-alive*
		    :verbose *dex-verbose*)
	(values (json-decode-octets/js result) code nil))
    (dex:http-request-failed (e)
      (values nil (dex:response-status e) (json-decode-octets/js (dex:response-body e))))))

;;;;
;;;; AWS support routines
;;;;
  
;;;
;;; if pool-id is "us-east-1_pppp1111"
;;; then
;;;   region -> "us-east"
;;;   pool -> "pppp1111"
;;;
(defun region/s (pool-id_s)
  (first (ppcre:split "_" pool-id_s)))

(defun pool/s (pool-id_s)
  (second (ppcre:split "_" pool-id_s)))

;;;
;;; so far, the URL to use for Cognito REST APIs is based on the region code.
;;; It may more complicated than the simple string concatentation method used
;;; here.  For example, I've seen (but not studied) code that special cases
;;; things in Canada.
;;;
(defun make-cognito-url/s (client_s region_s)
  (concatenate 'string "https://" client_s "." region_s ".amazonaws.com"))
	   
;;;
;;; convert n to hex string
;;; ensure even number of characters
;;; then, if the string begins with [89abcdef],
;;; prepend '00'
;;;
;;;
(defun ensure-even-length (s)
  (if (oddp (length s))
      (concatenate 'string "0" s)
      s))

(defun ensure-leading-00 (s)
  (assert (plusp (length s)))
  (if (position (aref s 0) "89abcdef")
      (concatenate 'string "00" s)
      s))

(defun integer-to-padded-hex-string (n)
  (ensure-leading-00 (ensure-even-length (integer-to-hex-string n))))

;;;
;;; ensure hs at least 64 characters with leading zero fill
;;;
(defun pad-hex-string (hs)
  (format nil "~64,1,0,'0@a" hs))

;;;
;;; Python pow(base exp modulus)
;;; cf.
;;;   https://stackoverflow.com/questions/8496182/calculating-powa-b-mod-n
;;;
(defun power-mod (base exp modulus)
  (labels
      ((power-mod-helper (base exp result)
	 (if (zerop exp)
	     result
	     (power-mod-helper (mod (* base base) modulus) (truncate exp 2) (if (oddp exp) (mod (* result base) modulus) result)))))
    (power-mod-helper (mod base modulus) exp 1)))

;;;
;;; generate_random_small_a() calls get_random(128) which calls os.urandom(128) which
;;; returns 1024 (128*8) random bits.
;;;
(defun get-big-random ()
  (random (expt 2 1024)))

(defun generate-random-small-a ()
  (mod (get-big-random) *n*))

(defun calculate-a (small-a)
  (let ((result (power-mod *g* small-a *n*)))
    (assert (not (zerop (mod result *n*))))
    result))

(defun sha256/ba (vector_ba)
  (ironclad:digest-sequence :sha256 vector_ba))

(defun sha256/hs64 (vector_ba)
  (pad-hex-string (ironclad:byte-array-to-hex-string (sha256/ba vector_ba))))

;;;
;;; return the integer sha256 hash of string_hs
;;;
(defun hash-hex-string (string_hs)
  (ironclad:octets-to-integer (sha256/ba (ironclad:hex-string-to-byte-array string_hs))))

(defun calculate-u (big-a srp-b)
  (hash-hex-string (concatenate 'string (integer-to-padded-hex-string big-a) (integer-to-padded-hex-string srp-b))))

;;;
;;; "Wed Aug 23 21:53:22 UTC 2017"
;;;
(defun timestamp/s (time)
  (local-time:format-timestring nil time
				:format '(:short-weekday " " :short-month " " :day " " (:hour 2) ":" (:min 2) ":" (:sec 2) " UTC " :year)
				:timezone local-time:+utc-zone+))

(defun hkdf (ikm salt)
  (let ((ikm_phs (integer-to-padded-hex-string ikm))
	(salt_phs (integer-to-padded-hex-string salt)))
    (let ((prk (ironclad:make-hmac (ironclad:hex-string-to-byte-array salt_phs) :sha256)))
      (ironclad:update-hmac prk (ironclad:hex-string-to-byte-array ikm_phs))
      (let ((hkdf (ironclad:make-hmac (ironclad:hmac-digest prk) :sha256)))
	(ironclad:update-hmac hkdf (string-to-octets (format nil "Caldera Derived Key~c" #\Soh)))
	(subseq (ironclad:hmac-digest hkdf) 0 16)))))

(defun client-secret-hash/s64 (e-mail_s client-id_s client-secret_s)
  (let ((hmac (ironclad:make-hmac (string-to-octets client-secret_s) :sha256)))
    (ironclad:update-hmac hmac (string-to-octets e-mail_s))
    (ironclad:update-hmac hmac (string-to-octets client-id_s))
    (cl-base64:usb8-array-to-base64-string (ironclad:hmac-digest hmac))))  

(defun password-authentication-key/ba (password_s large-a small-a k pool_s user-id-for-srp srp-b salt)
  (let ((u (calculate-u large-a srp-b)))
    (assert (not (zerop u)))
    (let* ((username-password-hash_hs (sha256/hs64 (string-to-octets (concatenate 'string pool_s user-id-for-srp ":" password_s))))
	   (x (hash-hex-string (concatenate 'string (integer-to-padded-hex-string salt) username-password-hash_hs)))
	   (s (power-mod (- srp-b (* k (power-mod *g* x *n*))) (+ small-a (* u x)) *n*)))
    (hkdf s u))))

(defun signature-string/b64s (hkdf_ba pool-id_s user-id_for-srp_s secret-block_ba timestamp_s)
  (let ((hmac (ironclad:make-hmac hkdf_ba :sha256)))
    (ironclad:update-hmac hmac (concatenate '(vector (unsigned-byte 8))
					    (string-to-octets pool-id_s)
					    (string-to-octets user-id_for-srp_s)
					    secret-block_ba
					    (string-to-octets timestamp_s)))
    (cl-base64:usb8-array-to-base64-string (ironclad:hmac-digest hmac))))

(defun verify-password-content/s (client-id_s timestamp_s username_s secret-block_b64s signature-string_b64s secret-hash_s64 user-email_s)
  (cl-json:encode-json-to-string `(("ChallengeName" . "PASSWORD_VERIFIER")
				   ("ClientId" . ,client-id_s)
				   ("ChallengeResponses" . (("USERNAME" . ,username_s)
							    ("PASSWORD_CLAIM_SECRET_BLOCK" . ,secret-block_b64s)
							    ("TIMESTAMP" . ,timestamp_s)
							    ("PASSWORD_CLAIM_SIGNATURE" . ,signature-string_b64s)
							    ,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)
										    ("EMAIL" . ,user-email_s))))))))

(defun verify-password (url_s password_s large-a small-a k client-id_s pool_s secret-hash_s64 user-email_s challenge-parameters)
  (let* ((user-id-for-srp_s (xjson:json-key-value :+USER-ID-FOR-SRP+ challenge-parameters))
	 (secret-block_b64s (xjson:json-key-value :+SECRET-BLOCK+ challenge-parameters))
	 (username_s (xjson:json-key-value :+USERNAME+ challenge-parameters))
	 (the-time (local-time:now))
	 (timestamp_s (timestamp/s the-time))
	 (hkdf_ba (password-authentication-key/ba password_s
						  large-a
						  small-a
						  k
						  pool_s
						  user-id-for-srp_s
						  (hex-string-to-integer (xjson:json-key-value :+SRP-B+ challenge-parameters))
						  (hex-string-to-integer (xjson:json-key-value :+SALT+ challenge-parameters))))
	 (secret-block_ba (cl-base64:base64-string-to-usb8-array secret-block_b64s))
	 (signature-string_b64s (signature-string/b64s hkdf_ba pool_s user-id-for-srp_s secret-block_ba timestamp_s)))
    (multiple-value-bind (result_js code response_js)
	(post url_s
	      '(("Content-type" . "application/x-amz-json-1.1")
		("X-Amz-Target" . "AWSCognitoIdentityProviderService.RespondToAuthChallenge"))
	      (verify-password-content/s client-id_s timestamp_s username_s secret-block_b64s signature-string_b64s secret-hash_s64 user-email_s))
      (let ((creds (xjson:json-key-value :*AUTHENTICATION-RESULT result_js)))
	(if creds
	    (values (append creds `((:*TIMESTAMP . ,(local-time:timestamp-to-universal the-time)))) code response_js)
	    (values result_js code response_js))))))

(defun srp-a-content/s (client-id_s username_s large-a secret-hash_s64 user-email_s)
  (cl-json:encode-json-to-string `(("AuthFlow" . "USER_SRP_AUTH")
				   ("ClientId" . ,client-id_s)
				   ("AuthParameters" . (("USERNAME" . ,username_s)
							("SRP_A" . ,(integer-to-hex-string large-a))
							,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)
										("EMAIL" . ,user-email_s)))))
				   ("ClientMetadata" . ,(xjson:json-empty)))))

(defun make-client-secret/s64 (client-secret client-id username)
  (if client-secret
      (client-secret-hash/s64 username client-id client-secret)
      nil))

(defun check-client-secret-parameters (client-secret_s user-email_s)
  (unless (or (null client-secret_s) (and client-secret_s user-email_s))
    (error "when client-secret is provided, user-email must also be provided")))

(defun authenticate-user (username password pool-id client-id &key (client "cognito-idp") (client-secret nil) (user-email nil))
  (check-client-secret-parameters client-secret user-email)
  (let* ((url_s (make-cognito-url/s client (region/s pool-id)))
	 (small-a (generate-random-small-a))
	 (large-a (calculate-a small-a))
	 (k (hash-hex-string (concatenate 'string "00" (integer-to-hex-string *n*) "0" (integer-to-hex-string *g*))))
	 (secret-hash_s64 (make-client-secret/s64 client-secret client-id username)))
    (multiple-value-bind (result_js code response_js)
	(post url_s
	      '(("Content-type" . "application/x-amz-json-1.1")
		("X-Amz-Target" . "AWSCognitoIdentityProviderService.InitiateAuth"))
	      (srp-a-content/s client-id username large-a secret-hash_s64 user-email))
      (if (equal (xjson:json-key-value :*CHALLENGE-NAME result_js) "PASSWORD_VERIFIER")
	  (multiple-value-bind (verify-result_js verify-code verify-response_js)
	      (verify-password url_s password large-a small-a k client-id (pool/s pool-id) secret-hash_s64 user-email (xjson:json-key-value :*CHALLENGE-PARAMETERS result_js))
	    (values verify-result_js verify-code verify-response_js))
	  (values result_js code response_js)))))

(defun reauthenticate-user (username refresh-token pool-id client-id &key (client "cognito-idp") (client-secret nil))
    (let* ((url_s (make-cognito-url/s client (region/s pool-id)))
	   (secret-hash_s64 (make-client-secret/s64 client-secret client-id username))
	   (the-time (local-time:now)))
      (multiple-value-bind (result_js code response_js)
	  (post url_s
		'(("Content-type" . "application/x-amz-json-1.1")
		  ("X-Amz-Target" . "AWSCognitoIdentityProviderService.InitiateAuth"))
		(cl-json:encode-json-to-string `(("AuthFlow" . "REFRESH_TOKEN_AUTH")
						 ("ClientId" . ,client-id)
						 ("AuthParameters" . (("USERNAME" . ,username)
								      ("REFRESH_TOKEN" . ,refresh-token)
								      ,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)))))
						 ("ClientMetadata" . ,(xjson:json-empty)))))
	(let ((creds (xjson:json-key-value :*AUTHENTICATION-RESULT result_js)))
	  (if creds
	      (values (append creds `((:*TIMESTAMP . ,(local-time:timestamp-to-universal the-time)))) code response_js)
	      (values result_js code response_js))))))

   
(defun sign-out (access-token pool-id &key (client "cognito-idp"))
  (let* ((url_s (make-cognito-url/s client (region/s pool-id))))
    (multiple-value-bind (result_js code response_js)
	(post url_s
	      '(("Content-type" . "application/x-amz-json-1.1")
		("X-Amz-Target" . "AWSCognitoIdentityProviderService.GlobalSignOut"))
	      (cl-json:encode-json-to-string `(("AccessToken" . ,access-token))))
      (if (equal code 200)
	  (values t code nil)
	  (values result_js code response_js)))))
