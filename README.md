###cl-cognito:  A Common Lisp Interface to Amazon Cognito.

The primary purpose of this libary is to be able to obtain Amazon Cognito access, id, and
refresh tokens based on Amazon Cognito user pool credentials.  A secondary purpose is to
provide other Cognito services over time.

These Amazon Cognito objects are used in this interface:

**username**      : Cognito username.  See Cognito -> User Pools -> Users and Groups.  The **username** is not the **user-email**.<br>
**password**      : Cognito password.<br>
**pool-id**       : See Cognito -> User Pools -> General Settings.<br>
**client-id**     : See Cognito -> App clients -> App client id.<br>
**service**       : "cognito-idp".  Other values may be possible, but this package doesn't know how to deal with them.<br>
**client-secret** : Optional.  See Cognito -> App clients -> App client id -> Show More Details -> App client secret.<br>
**user-email**    : Cognito e-mail.  See Cognito -> User Pools -> Users and Groups.<br>
**access-key**    : Your user security credentials.
**secret-key**    :


The nickname **cognito** can be used for the **cl-cognito** package.

[Function]<br>
**authenticate-user** (username password pool-id client-id &key (service "cognito-idp") (client-secret nil) (user-email nil) (new-password nil) (new-full-name nil) (new-phone nil) (new-email nil))

		=> result, code, response
		
		If **client-secret** is not nil then **user-email** must be provided.  On a password change where new user e-mail is required,
		both user-email and new-email must be the same.
		
		If new-password is not nil and a new password is required then the existing password will be changed.
		new-full-name, new-phone, and new-email will be sent to Congito if required and not nil. 
		
		On success, returns **result** which is a list of the form:
		
		((:*ACCESS-TOKEN . "eyJraW...")
		 (:*EXPIRES-IN . 3600)
	     (:*ID-TOKEN . "eyJraW...")
	     (:*REFRESH-TOKEN . "eyJjdH...")
	     (:*TOKEN-TYPE . "Bearer")
	     (:*TIMESTAMP . 3712515272))
		
		:*TIMESTAMP is the Lisp universal time when the Cognito request was made, so :*TIMESTAMP + :*EXPIRES-IN
		is when the tokens expire.  **cl-cognito** does not automatically refresh tokens.
		
		On error, **result** is nil.
		
		**code** is the HTTP response code.
		
		On success, **response** is nil.  On error, **response** is the decoded JSON response provided by Amazon.
		
		Example:
		
		An incorrect password will result in:
		
		result => NIL
		code => 400
		response => ((:----TYPE . "NotAuthorizedException")
 		             (:MESSAGE . "Incorrect username or password."))
 		             
 		A password that must be changed might result in:
 		
 		result => ((:*CHALLENGE-NAME . "NEW_PASSWORD_REQUIRED")
                   (:*CHALLENGE-PARAMETERS (:REQUIRED-ATTRIBUTES . "[]")
                   (:USER-ATTRIBUTES . "..."))
                   (:*SESSION . "..."))
		code => 200
		response => nil
 		             
 		A password that must be reset will result in:
 		
 		result => NIL
 		code => 400
 		response => ((:----TYPE . "PasswordResetRequiredException")
                     (:MESSAGE . "Password reset required for the user"))
                     
    	Use confirm-forgot-password to reset the password.

[Function]<br>
**new-password-required?** (result)

		Returns t if the result from **authenticate-user** indicates a new password is required.  If so,
		repeat the call to *authenticate-user** and set :new-passowrd to the new desired password.
		:new-full-name, :new-phone, and :new-mail may also need to be provided.
		
[Function]<br>
**new-password-attributes** (result)

		Returns a list of the attributes required for a password change if the result from **authenticate-user**
		indicates a new password is required.  Example:
		
		  ("userAttributes.email" "userAttributes.phone_number" "userAttributes.name")

[Function]<br>
**reauthenticate-user** (username refresh-token pool-id client-id &key (service "cognito-idp") (client-secret nil) (user-email nil))

		=> result, code, response
		
		Identical to **authenticate-user** but a **refresh-token** is provided in place of a password.
		If **client-secret** is not nil then *user-email* must be provided.
	
		((:*ACCESS-TOKEN . "eyJraW...")
		 (:*EXPIRES-IN . 3600)
		 (:*ID-TOKEN . "eyJraW...")
		 (:*TOKEN-TYPE . "Bearer")
		 (:*TIMESTAMP . 3712528761))

		If **client-secret** is nil then it appears that AWS doesn't care what *username* is.  YMMV.

[Function]<br>
**forgot-password** (username pool-id client-id &key (service "cognito-idp") (client-secret nil))

		Causes a confirmation code which can be used by confirm-forgot-password to be sent to the user.

		=> result, code, response

		If successful, result is t.
		
		Note that this doesn't expire the old password -- the old password can still be used until changed
		by confirm-forgot-password.

[Function]<br>
**confirm-forgot-password** (username confirmation-code new-password pool-id client-id &key (service "cognito-idp") (client-secret nil))

		Change password to new-password.
		
		=> result, code, response

		If successful, result is t.
		
[Function]<br>
**change-password** (access-token pool-id old-password new-password &key (service "cognito-idp"))

		Change passowrd
		
		=> result, code response
		
		If successful, result is t
		
[Function]<br>
**sign-out** (access-token pool-id &key (service "cognito-idp"))

		=> result, code, response
		
		Global sign out user.
		
		Returns t on success, nil on failure.  **code** and **response** can be used to
		determine failure cause.

[Function]<br>
**list-users** (pool-id access-key secret-key &key (service "cognito-idp") (pagination-token nil))

		List users in pool.  Note:  A non-nil pagination-token has not been tested.
	
		=> result, code, response
	
		On success, result is the list of users and their associated information.
	
[Function]<br>
**admin-create-user** (username pool-id temporary-password access-key secret-key<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&key (service "cognito-idp") (delivery 'email) (force-alias nil)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
(message-action 'suppress) (user-attributes nil) (validation-data nil))

		delivery is 'email or 'sms or '(email sms)
		message-action is 'resend or 'suppress
		user-attributes is ((attribute1 . value1) (attribute2 . value2) ...)
		validation-data is ((attribute1 . value1) (attribute2 . value2) ...)

		=> result, code, response

		Create user.  On success, **result** is the response from AdminCreateUser
		
		Example:
		
		(defun create-aws-user (username real-name company e-mail phone-number temporary-password)
		  (cognito:admin-create-user username *pool-id* temporary-password *access-key*  *secret-key*
			                         :user-attributes `(("email" . ,e-mail)
						                                ("email_verified" . "true")
						                                ("name" . ,real-name)
						                                ("phone_number" . ,phone-number)
						                                ("custom:company" . ,company)))))
						                                  
		(create-aws-user "test-user" "John Doe" "John Doe, Inc." "john@doe.com" "+15556678329" "ChangeMe.")

		=>
		((:*USER
		 (:*ATTRIBUTES
		 ((:*NAME . "sub") (:*VALUE . "4836786e-f43c-47d9-b2e2-076aad5d9d8e"))
		 ((:*NAME . "email_verified") (:*VALUE . "true"))
		 ((:*NAME . "name") (:*VALUE . "John Doe"))
		 ((:*NAME . "phone_number") (:*VALUE . "+15556678329"))
		 ((:*NAME . "email") (:*VALUE . "john@doe.com"))
		 ((:*NAME . "custom:company") (:*VALUE . "John Doe, Inc.")))
		 (:*ENABLED . T) (:*USER-CREATE-DATE . 1.5076493e9)
		 (:*USER-LAST-MODIFIED-DATE . 1.5076493e9)
		 (:*USER-STATUS . "FORCE_CHANGE_PASSWORD") (:*USERNAME . "test-user")))
		200
		nil

[Function]<br>
**admin-update-user-attributes** (username pool-id attributes access-key secret-key &key (service "cognito-idp"))

		user-attributes is ((attribute1 . value1) (attribute2 . value2) ...)
		
		=> result, code, response

		Update user attributes
		
		Example:
		
		(cognito:admin-update-user-attributes "test-user" *pool-id* '(("custom:company" . "Doe John, Ltd.")) *access-key* *secret-key*)
		
		=>
		T
		200
		NIL

[Function]<br>
**admin-get-user** (username pool-id access-key secret-key &key (service "cognito-idp"))

		=> result, code, response
		
		Get user attributes
		
		Example:
		
		(cognito:admin-update-user-attributes "test-user" *pool-id*  *access-key* *secret-key*)
		
		=>
		((:*ENABLED . T)
		 (:*USER-ATTRIBUTES
		  ((:*NAME . "sub") (:*VALUE . "4836786e-f43c-47d9-b2e2-076aad5d9d8e"))
		  ((:*NAME . "email_verified") (:*VALUE . "true"))
		  ((:*NAME . "name") (:*VALUE . "John Doe"))
		  ((:*NAME . "phone_number") (:*VALUE . "+15556678329"))
		  ((:*NAME . "email") (:*VALUE . "john@doe.com"))
		  ((:*NAME . "custom:company") (:*VALUE . "Doe John, Ltd.")))
		 (:*USER-CREATE-DATE . 1.5076493e9) (:*USER-LAST-MODIFIED-DATE . 1.50765e9)
		 (:*USER-STATUS . "FORCE_CHANGE_PASSWORD") (:*USERNAME . "test-user"))
		200
		NIL

[Function]<br>
**admin-reset-user-password** (username pool-id access-key secret-key &key (service "cognito-idp"))

		=> result, code, response

		Returns t on success, nil on failure.  **code** and **response** can be used to
		determine failure cause.

#### BUGS

The URL to use to interact with Cognito is constructed by the private function **(make-aws-url/s service\_s region\_s)**.<br>
No services other than "cognito-idp" and no regions other than those in the US have been tested.

It isn't clear that defining authenticate-user to take :new-full-name, :new-email, and :new-phone is the best design choice.

#### HTTP engine
[Dexador](http://quickdocs.org/dexador/) is used to process HTTPS requests.  The code encapsulates this in one function, so it would be easy
to use [Drakma](http://www.weitz.de/drakma/), instead.

#### Repository
[https://github.com/stablecross/cl-cognito](https://github.com/stablecross/cl-cognito)

####License
cl-cognito is available under a BSD-like license.  See the file LICENSE for details.

#### Contact
For any questions or comments, please feel free to email me, Bob Felts
<wrf3@stablecross.com>
