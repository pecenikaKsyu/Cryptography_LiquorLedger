
### Course: Cryptography & Security
### Author: Wu Ksenia-Qin Li

----

## Web Authentication & Authorisation
Some terminology to know before of all:
* **Identity** is a statement about who you are. Depending on the situation, this could be a name, email address,
account number, etc.
* **Authentication** - providing evidence that you really are who you identified yourself with (from the word
"authentic" - true, genuine).
* **Authorization** - checking that you are allowed to access the requested resource.

These terms are used in computer systems, where traditionally, identification means getting your account (identity) by
username or email; under authentication - verification that you know the password for this account, and under
authorization - verification of your role in the system and the decision to grant access to the requested page or
resource.

 ### Web Authentication

This protocol, described in the HTTP 1.0/1.1 standards, has existed for a very long time and is still actively used in
a corporate environment. For websites it works like this:

1. The server, when an unauthorized client accesses a protected resource, sends the HTTP status “401 Unauthorized” and
adds the “WWW-Authenticate” header indicating the authentication scheme and parameters.
2. The browser, upon receiving such a response, automatically displays a username and password input dialog. The user
enters their account details.
3. In all subsequent requests to this website, the browser automatically adds an “Authorization” HTTP header, which
transmits user data for authentication by the server.
4. The server authenticates the user based on the data in this header. The decision to grant access (authorization) is
made separately based on the user's role, ACL, or other account data.


The whole process is standardized and well-supported by all browsers and web servers. There are several authentication
schemes that differ in the level of security:

1. **Basic** is the simplest scheme, in which the username and password of the user are passed in the Authorization header
in unencrypted form (base64-encoded). However, when using the HTTPS (HTTP over SSL) protocol, it is relatively secure.

2. **Digest** is a challenge-response scheme where the server sends a unique nonce value and the browser sends an MD5
hash of the user's password computed using the specified nonce. A more secure alternative to the Basic scheme for
insecure connections, but subject to man-in-the-middle attacks (with the scheme replaced by basic). In addition, using
this scheme does not allow using modern hash functions to store user passwords on the server.
3. **NTLM** (known as Windows authentication) is also based on the challenge-response approach, in which the password is
not transmitted in its purest form. This scheme is not an HTTP standard, but is supported by most browsers and web servers.
Primarily used to authenticate Windows Active Directory users in web applications. Vulnerable to pass-the-hash attacks.
4. **Negotiate** is another Windows authentication scheme that allows the client to choose between NTLM and Kerberos
authentication. Kerberos is a more secure protocol based on the Single Sign-On principle. However, it can only function
if both the client and the server are in the intranet zone and are part of a Windows domain.

It is worth noting that when using HTTP authentication, the user has no standard option to log out of the web
application other than to close all browser windows.

 ### Authorization

**Authorization**  - granting a certain person or group of persons the rights to perform certain actions; as well as
the process of checking (confirming) these rights when trying to perform these actions.

From the point of view of any information system, this is the process of making a decision on granting access to the
subject to perform an operation based on any knowledge about the subject. By this point, the subject, as a rule, should
already be identified (we need to know who he is) and authenticated (his identity is confirmed).

The implementation of authorization in the development of a corporate information system or a product focused on the
corporate sector is a very complex and responsible task, which is often given insufficient attention at the design
stage and the initial development stage, which leads to a “crutch” implementation in the future.

There are usually two sources of authorization requirements in a corporate information system: business and information
security. In general, business wants to keep secrets secret and grant permissions to users according to their role in
the business process, while security wants to ensure that each user has a minimum level of authority and audit access.

## Objectives:

1. Take what you have at the moment from previous laboratory works and put it in a web service / serveral web services.
2. Your services should have implemented basic authentication and MFA (the authentication factors of your choice).
3. Your web app needs to simulate user authorization and the way you authorise user is also a choice that needs to be
done by you.
4. As services that your application could provide, you could use the classical ciphers. Basically the user would like
to get access and use the classical ciphers, but they need to authenticate and be authorized.

## Implementation description
In this project you could see created a web service where you can register, log in using 2FA, and use the
encryption/decryption services by sending requests to endpoints.The server runs on `http://127.0.0.1:5000`

### TOTP Authentication (2FA)
TOTP is used to implement the two-factor authentication.

One-time password authentication is usually used in addition to password authentication to implement two-factor
authentication (2FA). In this concept, the user needs to provide two types of login data: something he knows
(eg a password) and something he owns (eg a device for generating one-time passwords). The presence of two factors can
significantly increase the level of security, which can be. required for certain types of web applications.
Unique numeric passwords are generated with a standardized algorithm that uses the current time as an input.
The time-based passwords are available offline and provide user-friendly, increased account security when used as a
second factor. When registering, the user has to provide an email and a password, then a link with the QR code will be
sent back. It has to be scanned using Google Authenticator.

### register

Request is made:

```json
    {"email": "aut.user.try@gmail.com", "password": "Moscow01"}
```

Response is get:

```
Access the link to get the Qr Code. Scan it using Google Authenticator:
https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=otpauth://totp/Laboratory%20Work%20Nr.5:user1%40gmail.com?secret=MEEQ2R6V4S7HL5PDEO2SGWUTDCWZ4DBZ&issuer=Laboratory%20Work%20Nr.5
```

An OTP will be generated in the Google Authenticator app, and it will be used for logging in.

#### Register Endpoint

With pyotp library, a secret string is assigned to the user. After that, TOTP is used and create a specific URL for the
QR code.

When logging in, the user provides email, password, and the otp generated in Google Authenticator. The server checks if
the data is correct, and sends a success message with a token that has to be used when sending requests to service
endpoints.

```python
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        register_data = {
            'email': data['email'],
            'password': data['password']
        }
        email = register_data['email']
        password = register_data['password']
        user_type = "user"
        secret_string = pyotp.random_base32()
        totp = pyotp.TOTP(secret_string)
        print("Creating user")
        create_user(email, password, user_type, secret_string)
        totp_uri = totp.provisioning_uri(name=email, issuer_name="Laboratory Work Nr.5")
        qr_uri = "https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=" + totp_uri
        return f'Access the link to get the Qr Code. Scan it using Google Authenticator: {qr_uri}'
    except Exception as e:
        print(str(e))
        return "Error occured! Please, check if you introduced the correct data, or ensure if you haven't registered " \
               "with this email already. "
```


### Login Endpoint

The server checks if the email, password and otp are correct, then logs the user in, by adding in a in-memory database,
in this case a dictionary, the email and a random token, which will be used when sending requests.

```python
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        login_data = {
            'email': data['email'],
            'password': data['password'],
            'otp': data['otp']
        }
        email = login_data['email']
        password = login_data['password']
        otp = login_data['otp']
        user = get_user(email)
        user_password = user[0][1]
        totp = user[0][3]
        totp = pyotp.TOTP(totp)
        if user_password != password:
            return "Incorrect password."
        if totp.now() != otp:
            return "Incorrect OTP code."
        alphabet = string.ascii_letters + string.digits
        if email not in tokens:
            token = ''.join(secrets.choice(alphabet) for i in range(8))
            tokens.update({email: token})
            return f'Login success! Use the token ({token}) to make requests.'
        token = tokens[email]
        print(tokens)
        return f'Already logged in! Use the token ({token}) to make requests.'
    except Exception as e:
        print(str(e))
        return "Something went wrong! Check if you introduced the correct data."

```

### Caesar Cipher Endpoint

```python
@app.route('/caesar', methods=['POST'])
def caesar():
    try:
        data = request.get_json()
        login_data = {
            'token': data['token'],
            'message': data['message'],
            'key': data['key']
        }
        token = login_data['token']
        user_message = login_data['message']
        user_key = login_data['key']
        if token not in tokens.values():
            return "Something went wrong! Check if you provided the correct token or if you are logged in."
        print("Caesar Cipher")
        caesarCipher = CaesarCipher()
        message = user_message.upper()
        key = int(user_key)
        encrypted_message = caesarCipher.encrypt(message, key)
        decrypted_message = caesarCipher.decrypt(encrypted_message, key)
        return f'The original message: {message}, The encrypted message: {encrypted_message}, The decrypted message: ' \
               f'{decrypted_message}'
    except Exception as e:
        print(str(e))
        return "Error occurred!"
```

### Other endpoints from implemented ciphers:
### Vigenere, Caesar w/ Permutation, and Playfair

```python
{"token": "Qr[*?Bdi", "message": "university", "key": "utm"}
```
----

### Authorization (RBAC)

Some services provided cannot been accessed by the User profile because of security reasons. In order to get full
access to all options is needed to have the Admin profile role. For example:

### Simple User

Request:
```python
{"token": "Qr[*?Bdi", "message": "university", "key": "utm"}
```

Response:
```
You don't have enough access rights.
```

To get the admin role, an admin account has to be created. It can be done by accessing `/admin` endpoint and
registering using `4#17QZksEGi2` password.

### Admin Profile

Request:
```json
    {"email": "admin1@gmail.com", "password": "Washington01", "secret": "4#17QZksEGi2"}
```

Response:
```
Access the link to get the Qr Code. Scan it using Google Authenticator:
https://chart.googleapis.com/chart?cht=qr&chs=500x500&chl=otpauth://totp/Laboratory%20Work%20Nr.5:admin%40gmail.com?secret=J7UWQBYLGII3A4A53VGSZN5QWAOUPKNR&issuer=Laboratory%20Work%20Nr.5
```

Request:
```python
{"token": "#LRSxEJL", "message": "university", "key": "utm"}
```

Response:
```
The original message: UNIVERSITY, The encrypted message: 11000101010000011100010100110100010011111001010000111000111001011011011111011010, The decrypted message: UNIVERSITY
```

### Other Accesible only by Admin Profile options:

### Asymmetric and Hashing
```
{"token": "#LRSxEJL", "message": "university"}
```

----

### Database

To perform operations in this laboratory work is needed to implement SQLite, and create the Users Table.

```python
def create_initial_db_resources():
    cur.execute(
        "CREATE TABLE IF NOT EXISTS Users(email varchar unique, password varchar, user_type varchar, totp varchar)")
    cur.execute("SELECT * FROM Users")
    print(cur.fetchall())
```

Here is how the user profile is created:

```python
def create_user(email, password, user_type, totp):
    cur.execute("INSERT INTO Users(email, password, user_type, totp) values(:email, :password, :user_type, :totp)", {
        'email': email,
        'password': password,
        'user_type': user_type,
        'totp': totp
    })
    print("Created user successfully")
    con.commit()
```

And here is how the user is get by the email:

```python
def get_user(email):
    try:
        cur.execute("SELECT email, password, user_type, totp FROM Users WHERE email = :email", {
            'email': email
        })
        print("User found successfully")
        return cur.fetchall()
    except Exception as e:
        print("Exception occurred while checking for the user")
        raise e
```


## Conclusions / Screenshots / Results

Both Authentication and Authorization area units are utilized in respect of knowledge security that permits the safety
of an automatic data system. Each area unit terribly crucial topics usually related to the online as key items of its
service infrastructure. However, each of the terms area units is completely different with altogether different ideas.
Whereas indeed, they’re usually employed in an equivalent context with an equivalent tool, they’re utterly distinct
from one another.

Access to a resource is protected by both authentication and authorization. If you can't prove your identity, you won't
be allowed into a resource. And even if you can prove your identity, if you are not authorized for that resource, you
will still be denied access.

Implementing this two important for Informational Security technologies for the final laboratory work gave a hand to me
to broaden the understanding of how modern security works in web technologies. The purpose of authentication, the forms
of authentication. Typically, authentication protects items of value, and in the information age, it protects systems
and data.

Authorization is an undeservedly overlooked topic, both in publications and directly in the development process.
Two-factor authentication via SMS will be attached to the site by a child. Correctly implementing authorization in a
corporate system without putting on crutches is the most difficult task that seniors and architects break spears about,
and many popular commercial products (for example, Atlassian Jira) are on crutches due to the complexity of the
requirements.
