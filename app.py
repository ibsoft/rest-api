import logging
import os
import sys
from flask import Flask, request, jsonify
import jwt
import time
import hmac
import hashlib
import sqlite3
import json
from passlib.hash import pbkdf2_sha256
from configparser import ConfigParser
import sms_otp
from flask import g
import datetime
import hmac
import hashlib
import pytz


app = Flask(__name__)

tz = pytz.timezone('Europe/Athens')


@app.before_first_request
def before_first_request():
    log_level = logging.INFO

    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)

    root = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(root, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    log_file = os.path.join(logdir, 'app.log')
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)
    app.logger.addHandler(handler)

    app.logger.setLevel(log_level)
    
    defaultFormatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(defaultFormatter)

    



# Parsing Config file
config = ConfigParser()
config.read(os.path.join(sys.path[0], 'appconf.conf'))

print(config.sections())
    
app.config['secret_key'] = config.get('APP', 'app_key')

# Set expiration time to 1 minute from now
#expiration_time = time.time() + 120

# Set expiration time to 1 day from now
#expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)


#expiration_time = datetime.datetime.now() + datetime.timedelta(seconds=120)



######################################################################

# Send OTP with SMS
#ssh = sms_otp.RemoteSSH('example.com', 22, 'username', 'password')
#result = ssh.send_command('ls -l')


def generate_totp(key, interval=30):
    """Generate a time-based one-time password (TOTP)"""
    curr_time = int(time.time())
    curr_interval = curr_time // interval
    msg = bytearray()
    msg.extend(curr_interval.to_bytes(8, 'big'))
    hash_val = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hash_val[-1] & 0x0f
    truncated_hash = hash_val[offset:offset + 4]
    otp_val = int.from_bytes(truncated_hash, 'big') & 0x7fffffff
    return '{:06d}'.format(otp_val % 1000000)


def get_users(database_path):
    # Connect to the SQLite database
    conn = sqlite3.connect(database_path)

    # Create a cursor object to execute SQL queries
    cursor = conn.cursor()

    # Execute a SELECT query to retrieve all users and their passwords
    cursor.execute("SELECT username, password FROM users")

    # Fetch all rows returned by the SELECT query
    rows = cursor.fetchall()

    # Create an empty dictionary to store the usernames and passwords
    users = {}

    # Iterate over each row and add the username and password to the dictionary
    for row in rows:
        username, password = row
        users[username] = password

    # Convert the dictionary to a JSON array and return it
    return json.dumps(users)


def validate_user(database_path, username, password):
    # Connect to the SQLite database
    conn = sqlite3.connect(database_path)

    # Create a cursor object to execute SQL queries
    cursor = conn.cursor()

    # Execute a SELECT query to retrieve the hashed password for the given username
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    # Check if the row exists and the password is correct
    if row and pbkdf2_sha256.verify(password, row[0]):
        return True
    else:
        return False

# Load the users from the database into a dictionary
users_json = get_users(os.path.join(sys.path[0], 'users.db'))
users = json.loads(users_json)




#Login
@app.route('/login', methods=['GET','POST'])
def login():
    auth = request.authorization
  
    #Set Token Expiration time  
    expiration_time = datetime.datetime.now() + datetime.timedelta(seconds=120)
    
    #Mask user password
    masked_password = "*" * (len(auth.password) - 4) + auth.password[-4:]
    
    app.logger.info('Got Authentication request')
    
    if request.method == 'POST':
        if not auth or not auth.username or not auth.password:
            app.logger.info('Login: Could not verify'+ auth.username + ' ' + auth.password)
            return jsonify({'message': 'Could not verify'}), 401
            
        # Validate the user credentials
        if auth.username in users and validate_user(os.path.join(sys.path[0], 'users.db'), auth.username, auth.password):
            print("Valid user")

            app.logger.info('Login: User validated '+ auth.username +' '+ masked_password)

            secret_key =  config.get('SECRET_KEY', 'key')
            
            with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key FROM users WHERE username=?", (auth.username,))
                result = cur.fetchone()
                app.logger.info('Login: Got user OTP Key drom database')
                if not result:
                    app.logger.warning('Login: Cannot get OTP from database for user '+ auth.username)
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
                       
            otp = generate_totp(otp_key.encode())
            #token = jwt.encode({'otp': otp}, client_token)
            token = jwt.encode({'otp': otp, 'exp': expiration_time, 'client': auth.username}, secret_key)
            app.logger.info('Login: Generated token for user '+ auth.username + ' token: '+ token )
            app.logger.info('Login: Closing connection')
            
            return jsonify({'token': token}), 200
        else:
            print("Invalid user")
            app.logger.error('Login: Invalid credentials '+ auth.username)
            return jsonify({'message': 'Invalid credentials'}), 401



# Function to add padding characters
def fix_padding(token):
    # Calculate the number of padding characters required
    padding_length = len(token) % 4
    padding = '=' * padding_length
    
    # Add the padding characters to the token
    return token + padding




@app.route('/protected', methods=['GET'])
def protected():
    # Get token from request headers
    auth_header = request.headers.get('Authorization')
    token = None
    if auth_header:
        app.logger.info('Protected: Got Auth Header '+ auth_header )
        token = auth_header.split(" ")[1]
        app.logger.info('Protected: Got Token '+ token )
    # Check if token exists and is not empty
    if not token:
        app.logger.error('Protected: Token missing')
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        # Decode token and get expiration time
        secret_key = config.get('SECRET_KEY', 'key')
        app.logger.info('Protected: Decoded token')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        expiration_time = decoded.get('exp')
        app.logger.info('Protected: Got Expiration Date '+ str(expiration_time ))
        #Get client name
        client = decoded.get('client')
        app.logger.info('Protected: Got Client '+ str(client) )
        
        
        with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key FROM users WHERE username=?", (client,))
                result = cur.fetchone()
                app.logger.info('Protected: Got client key from database ')
                
                if not result:
                    app.logger.error('Protected: User missconfiguration')
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
        
        app.logger.info('Protected: Checking if token expired '+ str(datetime.datetime.utcnow().timestamp()) + ' ' + str(expiration_time))
        
        # Create a timezone object for Europe/Athens
        timezone = pytz.timezone('Europe/Athens')

        # Get the current time with timezone info
        current_time = datetime.datetime.now(timezone)

        # Get the timestamp in seconds
        timestamp = int(current_time.timestamp())

        
        app.logger.info(timestamp)
        app.logger.info(expiration_time)
        
        # Check if token is expired
        if datetime.datetime.now().timestamp() > expiration_time:
            app.logger.error('Protected: Token Expired!')
            return jsonify({'message': 'Token expired'}), 401
        app.logger.info('Protected: Token Expiration Looks Good! ')
        app.logger.info('Protected: Token is valid!')
        # Token is valid
        data = generate_totp(otp_key.encode())
        app.logger.info('Protected: Return data to client!')
        app.logger.info('Protected: Closing connection')
        return jsonify({'data': data}), 200
        
    except jwt.InvalidTokenError as e:
        print(e)
        
        app.logger.error('Protected: Invalid Token: ' + str(e))
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(debug=True)



#curl -X POST -u john:password123 http://localhost:5000/login
#curl -X GET http://localhost:5000/protected -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvdHAiOiI0MzU2ODQiLCJleHAiOjE2Nzg5NjA3MjZ9.BXmwfp8afjMMOL-EuQWeWyZq7P4UIX7VfDmHyNaL_aY
#gammu -c /etc/gammu-smsdrc sendsms TEXT 6977456030 -text "'lalakis'"

