###cl-cognito:  A Common Lisp Interface to Amazon Cognito.

The primary purpose of this libary is to be able to obtain Amazon Cognito access, id, and
refresh tokens based on Amazon Cognito user pool credentials.

These Amazon Cognito objects are used in this interface:

**username**      : Cognito username.  See Cognito -> User Pools -> Users and Groups.  The **username** is not the **user-email**.<br>
**password**      : Cognito password.<br>
**pool-id**       : See Cognito -> User Pools -> General Settings.<br>
**client-id**     : See Cognito -> App clients -> App client id.<br>
**client**        : "cognito-idp".  Other values may be possible, but this package doesn't know how to deal with them.<br>
**client-secret** : Optional.  See Cognito -> App clients -> App client id -> Show More Details -> App client secret.<br>
**user-email**    : Cognito e-mail.  See Cognito -> User Pools -> Users and Groups.<br>

The nickname **cognito** can be used for the **cl-cognito** package.

[Function]<br>
**authenticate-user** (username password pool-id client-id &key (client "cognito-idp") (client-secret nil) (user-email nil))

		=> result, code, response
		
		If **client-secret** is not nil then **user-email** must be provided.
		
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


[Function]<br>
**reauthenticate-user** (username refresh-token pool-id client-id &key (client "cognito-idp") (client-secret nil) (user-email nil))

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
**sign-out** (access-token pool-id &key (client "cognito-idp"))

		=> result, code, response
		
		Global sign out user.
		
		Returns t on success, nil on failure.  **code** and **response** can be used to
		determine failure cause.
		
#### BUGS

The URL to use to interact with Cognito is constructed by the private function **(make-cognito-url/s client\_s region\_s)**
No clients other than "cognito-idp" and no regions other than those in the US have been tested.

#### HTTP engine
[Dexador](http://quickdocs.org/dexador/) is used to process HTTPS requests.  The code encapsulates this in one function, so it would be easy
to use [Drakma](http://www.weitz.de/drakma/), instead.

#### Repository
[https://github.com/stablecross/cl-cognito](https://github.com/stablecross/cl-cognito)

####License
cl-cognito is available under a BSD-like license.  See the file LICENSE for
details.

#### Contact
For any questions or comments, please feel free to email me, Bob Felts
<wrf3@stablecross.com>
