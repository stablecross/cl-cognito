;;; Copyright (c) 2017-2018 William R. Felts III, All Rights Reserved
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

(defparameter *nl* (format nil "~c" #\Newline))

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
  (let ((string (octets-to-string octets)))
    (if (equalp string "")
	nil
	(json:decode-json-from-string string))))

;;;
;;; convert n to hex string
;;; ensure even number of characters
;;; then, if the string begins with [89abcdef],
;;; prepend '00'
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

(defun sha256/ba (vector_ba)
  (ironclad:digest-sequence :sha256 vector_ba))

(defun ba/hs64 (vector_ba)
  (pad-hex-string (ironclad:byte-array-to-hex-string vector_ba)))

(defun sha256/hs64 (vector_ba)
  (ba/hs64 (sha256/ba vector_ba)))

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
(defun post (url_s headers content_s)
  (handler-case
      (multiple-value-bind (result code)
	  (dex:post url_s
		    :headers headers
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
(defun make-aws-host/s (service_s region_s)
  (concatenate 'string service_s "." region_s ".amazonaws.com"))

(defun make-aws-endpoint (host_s)
  (concatenate 'string "https://" host_s))

(defun make-aws-url/s (service_s region_s)
  (make-aws-endpoint (make-aws-host/s service_s region_s)))

;;;
;;; http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
;;;
;;;  The time stamp must be in UTC and in the following ISO 8601 format: YYYYMMDD'T'HHMMSS'Z'.
;;;  For example, 20150830T123600Z is a valid time stamp.
;;;
(defun aws-timestamp (the-time)
    (local-time:format-timestring nil the-time
				:format '(:year (:month 2) (:day 2) "T" (:hour 2) (:min 2) (:sec 2) "Z")
				:timezone local-time:+utc-zone+))

;;;
;;; YYYYMMDD
;;;
(defun aws-datestamp (the-time)
    (local-time:format-timestring nil the-time
				:format '(:year (:month 2) (:day 2))
				:timezone local-time:+utc-zone+))
  

(defun aws4-credential-scope (the-time region service)
  (format nil "~a/~a/~a/aws4_request" (aws-datestamp the-time) region service))

(defun aws-sign (msg key)
  (let ((hmac (ironclad:make-hmac key :sha256)))
    (ironclad:update-hmac hmac (string-to-octets msg))
    (ironclad:hmac-digest hmac)))

;;;
;;; http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
;;; 
(defun aws4-signing-key (secret-key the-time region service)
  (let ((key (string-to-octets (concatenate 'string "AWS4" secret-key)))
	(date (aws-datestamp the-time)))
    (aws-sign "aws4_request" (aws-sign service (aws-sign region (aws-sign date key))))))

;;;
;;; http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
;;;
(defun trim-white (s)
  (string-trim '(#\Space #\Tab) s))

(defun trim-downcase-header (header)
  (cons (string-downcase (trim-white (car header))) (cdr header)))

(defun format-canonical-header-string (canonical-headers &optional (result ""))
  (let ((header (first canonical-headers)))
    (if (null header)
	result
	(format-canonical-header-string (rest canonical-headers) (format nil "~a~a:~a~c" result (car header) (cdr header) #\Newline)))))

;;;
;;; '(("a" . 1) ("b" . 2) ("c" . 3)) -> "a;b;c"
;;;
(defun format-canonical-signed-headers-string (canonical-headers &optional (result "") (separator ""))
  (let ((header (first canonical-headers)))
    (if (null header)
	result
	(format-canonical-signed-headers-string (rest canonical-headers) (format nil "~a~a~a" result separator (car header)) ";"))))

;;;
;;; take a list of ("a" . b) pairs, trim and downcase the car ("a"),
;;; then sort
;;;
(defun canonical-headers (headers)
  (sort (mapcar #'trim-downcase-header headers) #'string< :key #'car))

(defun aws4-authorization-string (aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)
  (when (and access-key secret-key)
    (let* ((canonical-headers (canonical-headers (cons (cons "host" aws-host) base-headers)))
	   (signed-headers-string (format-canonical-signed-headers-string canonical-headers))
	   (payload-hash (sha256/hs64 (string-to-octets content_s)))
	   (canonical-request (concatenate 'string "POST" *nl* "/" *nl* "" *nl* (format-canonical-header-string canonical-headers) *nl* signed-headers-string *nl* payload-hash))
	   (algorithm "AWS4-HMAC-SHA256")
	   (credential-scope (aws4-credential-scope the-time region_s service))
	   (string-to-sign (concatenate 'string algorithm  *nl* amz-time *nl* credential-scope *nl* (sha256/hs64 (string-to-octets canonical-request))))
	   (signature (ba/hs64 (aws-sign string-to-sign (aws4-signing-key secret-key the-time region_s service)))))
      (concatenate 'string  algorithm " " "Credential=" access-key "/" credential-scope ", SignedHeaders=" signed-headers-string ", Signature=" signature))))

(defun aws4-authorization-header (aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)
  (let ((authorization-string (aws4-authorization-string aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)))
    (when authorization-string
      (list (cons "Authorization" authorization-string)))))

;;;
;;; service = "cognito-idp"
;;; target = "AWSCognitoIdentityProviderService.AdminGetUser"
;;;
;;; => result_js result-code response_js
;;;    if result-code is 200, result_js will be forced to t if it is nil,
;;;       otherwise result_js passed unchanged
;;;
(defun aws4-post (service pool-id target content &key (access-key nil) (secret-key nil) (the-time (local-time:now)))
  (assert (equal (null access-key) (null secret-key)))
  (let* ((region_s (region/s pool-id))
	 (aws-host (make-aws-host/s service region_s))
	 (content_s (cl-json:encode-json-to-string content))
	 (amz-time (aws-timestamp the-time))
	 (base-headers `(("Content-type" . "application/x-amz-json-1.1")
			 ("X-Amz-Date" . ,amz-time)
			 ("X-Amz-Target" . ,target))))
    (multiple-value-bind (result_js result-code response_js)
	(post (make-aws-endpoint aws-host)
	      (append base-headers (aws4-authorization-header aws-host base-headers content_s the-time amz-time region_s service access-key secret-key))
	      content_s)
      (if (equal result-code 200)
	  (if result_js
	      (values result_js result-code response_js)
	      (values t result-code response_js))
	  (values result_js result-code response_js)))))

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

(defun client-secret-hash/s64 (username client-id_s client-secret_s)
  (let ((hmac (ironclad:make-hmac (string-to-octets client-secret_s) :sha256)))
    (ironclad:update-hmac hmac (string-to-octets username))
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

(defun authenticate-verify-password (service pool-id the-time password_s large-a small-a k client-id_s secret-hash_s64 user-email_s challenge-parameters)
  (let* ((user-id-for-srp_s (xjson:json-key-value :+USER-ID-FOR-SRP+ challenge-parameters))
	 (secret-block_b64s (xjson:json-key-value :+SECRET-BLOCK+ challenge-parameters))
	 (username_s (xjson:json-key-value :+USERNAME+ challenge-parameters))
	 (timestamp_s (timestamp/s the-time))
	 (pool_s (pool/s pool-id))
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
    (aws4-post service pool-id
	       "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
	       `(("ChallengeName" . "PASSWORD_VERIFIER")
		 ("ClientId" . ,client-id_s)
		 ("ChallengeResponses" . (("USERNAME" . ,username_s)
					  ("PASSWORD_CLAIM_SECRET_BLOCK" . ,secret-block_b64s)
					  ("TIMESTAMP" . ,timestamp_s)
					  ("PASSWORD_CLAIM_SIGNATURE" . ,signature-string_b64s)
					  ,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)
								  ("EMAIL" . ,user-email_s))))))
	       :the-time the-time)))

;;;
;;; if attribute-value and atribute-name in required-attributes, return ((name . value))
;;;
(defun attribute (required-attributes attribute-name attribute-value)
  (and attribute-value (member attribute-name required-attributes :test #'equalp) (list (cons attribute-name attribute-value))))

(defun authenticate-change-password (service pool-id username_s client-id session-id secret-hash_s64
			new-password_s required-attributes new-full-name_s new-phone_s new-email_s)
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
	     `(("ChallengeName" . "NEW_PASSWORD_REQUIRED")
	       ("ClientId" . ,client-id)
	       ("ChallengeResponses" . (("USERNAME" . ,username_s)
					("NEW_PASSWORD" . ,new-password_s)
					,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)))
					,@(attribute required-attributes "userAttributes.name" new-full-name_s)
					,@(attribute required-attributes "userAttributes.phone_number" new-phone_s)
					,@(attribute required-attributes "userAttributes.email" new-email_s)))
	       ("Session" . ,session-id))))

(defun make-client-secret/s64 (client-secret client-id username)
  (if client-secret
      (client-secret-hash/s64 username client-id client-secret)
      nil))

(defun check-client-secret-parameters (client-secret_s user-email_s)
  (unless (or (null client-secret_s) (and client-secret_s user-email_s))
    (error "when client-secret is provided, user-email must also be provided")))

(defun new-password-required? (result_js)
  (and (listp result_js)
       (equal (xjson:json-key-value :*CHALLENGE-NAME result_js) "NEW_PASSWORD_REQUIRED")))

;;;
;;; make a list of required attributes, e.g. '("userAttributes.email" "userAttributes.phone")
;;;
(defun new-password-attributes (result_js)
  (let* ((challenge-parameters (xjson:json-key-value :*CHALLENGE-PARAMETERS result_js))
	 (required-attributes (xjson:json-key-value :REQUIRED-ATTRIBUTES challenge-parameters)))
    (json::decode-json-from-string (or required-attributes "{}"))))

(defun timestamp-result (the-time result_js result-code response_js)
  (let ((creds (xjson:json-key-value :*AUTHENTICATION-RESULT result_js)))
    (if creds
	(values (append creds `((:*TIMESTAMP . ,(local-time:timestamp-to-universal the-time)))) result-code response_js)
	(values result_js result-code response_js))))

(defun do-authenticate-user (the-time username password pool-id client-id service client-secret user-email
			     new-password new-full-name new-phone new-email)
  (check-client-secret-parameters client-secret user-email)
  (let* ((small-a (generate-random-small-a))
	 (large-a (calculate-a small-a))
	 (k (hash-hex-string (concatenate 'string "00" (integer-to-hex-string *n*) "0" (integer-to-hex-string *g*))))
	 (secret-hash_s64 (make-client-secret/s64 client-secret client-id username)))
    (multiple-value-bind (result_js result-code response_js)
	(aws4-post service pool-id
		   "AWSCognitoIdentityProviderService.InitiateAuth"
		   `(("AuthFlow" . "USER_SRP_AUTH")
		     ("ClientId" . ,client-id)
		     ("AuthParameters" . (("USERNAME" . ,username)
					  ("SRP_A" . ,(integer-to-hex-string large-a))
					  ,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)
								  ("EMAIL" . ,user-email)))))
		     ("ClientMetadata" . ,(xjson:json-empty)))
		   :the-time the-time)
      (if (equal (xjson:json-key-value :*CHALLENGE-NAME result_js) "PASSWORD_VERIFIER")
	  (let ((challenge-parameters (xjson:json-key-value :*CHALLENGE-PARAMETERS result_js)))
	    (multiple-value-bind (verify-result_js verify-code verify-response_js)
		(authenticate-verify-password service pool-id the-time password large-a small-a k client-id secret-hash_s64 user-email challenge-parameters)
	      (if (and (new-password-required? verify-result_js) new-password)
		  (let ((session-id (xjson:json-key-value :*SESSION verify-result_js))
			(required-attributes (new-password-attributes verify-result_js)))
		    (multiple-value-bind (change-result_js change-code change-response_js)
			(authenticate-change-password service pool-id (xjson:json-key-value :+USER-ID-FOR-SRP+ challenge-parameters) client-id session-id secret-hash_s64
						      new-password required-attributes new-full-name new-phone new-email)
		      (values change-result_js change-code change-response_js)))
		  (values verify-result_js verify-code verify-response_js))))
	  (values result_js result-code response_js)))))

(defun authenticate-user (username password pool-id client-id
			  &key (service "cognito-idp")
			    (client-secret nil) (user-email nil)
			    (new-password nil) (new-full-name nil) (new-phone nil) (new-email nil))
  (let ((the-time (local-time:now)))
    (multiple-value-bind (result_js result-code response_js)
	(do-authenticate-user the-time username password pool-id client-id service client-secret user-email new-password new-full-name new-phone new-email)
      (multiple-value-bind (time-result_js time-result-code time-response_js)
	  (timestamp-result the-time result_js result-code response_js)
	(values time-result_js time-result-code time-response_js)))))

(defun reauthenticate-user (username refresh-token pool-id client-id &key (service "cognito-idp") (client-secret nil))
    (let* ((secret-hash_s64 (make-client-secret/s64 client-secret client-id username))
	   (the-time (local-time:now)))
      (multiple-value-bind (result_js result-code response_js)
	  (aws4-post service pool-id
		     "AWSCognitoIdentityProviderService.InitiateAuth"
		     `(("AuthFlow" . "REFRESH_TOKEN_AUTH")
		       ("ClientId" . ,client-id)
		       ("AuthParameters" . (("USERNAME" . ,username)
					    ("REFRESH_TOKEN" . ,refresh-token)
					    ,@(if secret-hash_s64 `(("SECRET_HASH" . ,secret-hash_s64)))))
		       ("ClientMetadata" . ,(xjson:json-empty)))
		     :the-time the-time)
	(multiple-value-bind (time-result_js time-result-code time-response_js)
	    (timestamp-result the-time result_js result-code response_js)
	  (values time-result_js time-result-code time-response_js)))))
   
(defun sign-out (access-token pool-id &key (service "cognito-idp"))
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.GlobalSignOut"
	     `(("AccessToken" . ,access-token))))

(defun change-password (access-token pool-id old-password new-password &key (service "cognito-idp"))
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.ChangePassword"
	     `(("AccessToken" . ,access-token)
	       ("PreviousPassword" . ,old-password)
	       ("ProposedPassword" . ,new-password))))
       
(defun forgot-password (username pool-id client-id &key (service "cognito-idp") (client-secret nil))
  (let ((secret-hash_s64 (make-client-secret/s64 client-secret client-id username)))
    (aws4-post service pool-id
	       "AWSCognitoIdentityProviderService.ForgotPassword"
	       `(("ClientId" . ,client-id)
		 ("Username" . ,username)
		 ,@(if secret-hash_s64 `(("SecretHash" . ,secret-hash_s64)))))))

;;;
;;; confirmation code can be either a number or a string
;;;
(defun confirm-forgot-password (username confirmation-code new-password pool-id client-id &key (service "cognito-idp") (client-secret nil))
  (let* ((secret-hash_s64 (make-client-secret/s64 client-secret client-id username)))
    (aws4-post service pool-id
	       "AWSCognitoIdentityProviderService.ConfirmForgotPassword"
	       `(("ClientId" . ,client-id)
		 ("Username" . ,username)
		 ("ConfirmationCode" . ,(format nil "~a" confirmation-code))
		 ("Password" . ,new-password)
		 ,@(if secret-hash_s64 `(("SecretHash" . ,secret-hash_s64)))))))

(defun cognito-admin-op (operation username pool-id access-key secret-key service)
  (aws4-post service pool-id
	     operation
	     `(("Username" . ,username)
	       ("UserPoolId" . ,pool-id))
	     :access-key access-key
	     :secret-key secret-key))

;;;
;;; convert ((attribute . value) (attribute . value) ...)
;;; to ( (("Name" . attribute) ("Value"  .value))
;;;      (("Name" . attribute) ("Value" . value)) )
;;;
(defun name-value-list (attributes)
  (loop
     for (name . value) in attributes
     collect (list (cons "Name" name)
		   (cons "Value" value))))

(defun name-value-object (tag attributes)
  (if (null attributes)
      nil
      (list (list* tag (name-value-list attributes)))))

;;;
;;; delivery -> 'sms, or 'email or '(sms email)
;;;
(defun delivery-mediums (delivery)
  (coerce (mapcar #'symbol-name (if (atom delivery) (list delivery) delivery)) 'vector))

;;;
;;; 
;;;
;;; delivery -> 'email or 'sms or '(email sms)
;;; message-action -> 'resend or 'suppress
;;; user-attributes ((attribute . value) (attribute . value) ...)
;;; validation-data -> ((attribute . value) (attribute . value) ...)
;;;
(defun admin-create-user (username pool-id temporary-password access-key secret-key
			  &key (service "cognito-idp") (delivery 'email) (force-alias nil) (message-action 'suppress) (user-attributes nil) (validation-data nil))
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.AdminCreateUser"
	     `(("DesiredDeliveryMediums" . ,(delivery-mediums delivery))
	       ("ForceAliasCreation" . ,(xjson:json-bool force-alias))
	       ("MessageAction" . ,(symbol-name message-action))
	       ("TemporaryPassword" . ,temporary-password)
	       ,@(name-value-object "UserAttributes" user-attributes)
	       ("Username" . ,username)
	       ("UserPoolId" . ,pool-id)
	       ,@(name-value-object "ValidationData" validation-data))
	     :access-key access-key
	     :secret-key secret-key))
  
			  
(defun admin-get-user (username pool-id access-key secret-key &key (service "cognito-idp"))
  (cognito-admin-op "AWSCognitoIdentityProviderService.AdminGetUser" username pool-id access-key secret-key service))
							  
(defun admin-reset-user-password (username pool-id access-key secret-key &key (service "cognito-idp"))
    (cognito-admin-op "AWSCognitoIdentityProviderService.AdminResetUserPassword" username pool-id access-key secret-key service))

(defun admin-delete-user (username pool-id access-key secret-key &key (service "cognito-idp"))
  (cognito-admin-op "AWSCognitoIdentityProviderService.AdminDeleteUser" username pool-id access-key secret-key service))

;;;
;;; attributes is a list of attribute value pairs, e.g. '(("custom:company" . "CompanyName") ("anotherAttribute" . "attributeValue") ...)
;;;
(defun admin-update-user-attributes (username pool-id attributes access-key secret-key &key (service "cognito-idp"))
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.AdminUpdateUserAttributes"
	     `(("Username" . ,username)
	       ("UserPoolId" . ,pool-id)
	       ("UserAttributes" ,@(name-value-list attributes)))
	     :access-key access-key
	     :secret-key secret-key))
  
(defun list-users (pool-id access-key secret-key &key (service "cognito-idp") (pagination-token nil))
  (aws4-post service pool-id
	     "AWSCognitoIdentityProviderService.ListUsers"
	     `(("UserPoolId" . ,pool-id)
	       ,@(if pagination-token `(("PaginationToken" . ,pagination-token))))
	     :access-key access-key
	     :secret-key secret-key))
