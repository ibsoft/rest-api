import logging
import os
import sys
from flask import Flask, render_template, request, jsonify
import jwt
import time
import hmac
import hashlib
import sqlite3
import json
from passlib.hash import pbkdf2_sha256
from configparser import ConfigParser
from flask import g
import datetime
import hmac
import hashlib
import pytz
import time

from providers.mssql_provider import SqlToJson
from providers.sms_provider import RemoteSSH


app = Flask(__name__)




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
config = ConfigParser(interpolation=None)
config.read(os.path.join(sys.path[0], 'appconf.conf'))


tz = pytz.timezone('Europe/Athens')
    
app.config['secret_key'] = config.get('APP', 'app_key')

######################################################################

# Send OTP with SMS
#ssh = sms_otp.RemoteSSH('example.com', 22, 'username', 'password')
#result = ssh.send_command('ls -l')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404



def generate_totp(key, interval=60):
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
  

    
    if request.method == 'POST':
        #Set Token Expiration time  
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=60) 
        
        if not auth or not auth.username or not auth.password:
            app.logger.info('Login: Could not verify'+ auth.username + ' ' + auth.password)
            return jsonify({'message': 'Could not verify'}), 401
        
        #Mask user password
        masked_password = "*" * (len(auth.password) - 4) + auth.password[-4:]
        
        app.logger.info('Got Authentication request')
            
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

            app.logger.info('Login: Setting expiration timestamp '+str(expiration_time.timestamp()))
            
            token = jwt.encode({'otp': otp, 'exp': expiration_time, 'client': auth.username}, secret_key)
            
            app.logger.info('Login: Generated token for user '+ auth.username + ' token: '+ token )
            app.logger.info('Login: Closing connection')
            
            return jsonify({'token': token}), 200
        else:
            print("Invalid user")
            app.logger.error('Login: Invalid credentials '+ auth.username)
            return jsonify({'message': 'Invalid credentials'}), 401
    
    return render_template("404.html")

# OTP Provider

@app.route('/provider/otp', methods=['GET'])
def protected():
    # Get token from request headers
    auth_header = request.headers.get('Authorization')
    token = None
    if auth_header:
        app.logger.info('OTPProvider: Got Auth Header '+ auth_header )
        token = auth_header.split(" ")[1]
        app.logger.info('OTPProvider: Got Token '+ token )
    else:
        return render_template("404.html")
    # Check if token exists and is not empty
    if not token:
        app.logger.error('OTPProvider: Token missing')
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        # Decode token and get expiration time
        secret_key = config.get('SECRET_KEY', 'key')
        app.logger.info('OTPProvider: Decoding token')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        expiration_time = decoded.get('exp')
        app.logger.info('OTPProvider: Got Expiration Date '+ str(expiration_time ))
        #Get client name
        client = decoded.get('client')
        app.logger.info('OTPProvider: Got Client '+ str(client) )
        
        
        with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key FROM users WHERE username=?", (client,))
                result = cur.fetchone()
                app.logger.info('OTPProvider: Got client key from database ')
                
                if not result:
                    app.logger.error('OTPProvider: User missconfiguration')
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
        
        app.logger.info('OTPProvider: Checking if token expired '+ str(datetime.datetime.now().timestamp()) + ' ' + str(expiration_time))
        
        now = datetime.datetime.now()
        app.logger.info(now.strftime("%Y-%m-%d %H:%M:%S"))
        app.logger.info(datetime.datetime.fromtimestamp(expiration_time))
        
        # Check if token is expired
        if datetime.datetime.now().timestamp() > expiration_time:
            app.logger.error('OTPProvider: Token Expired!')
            return jsonify({'message': 'Token expired'}), 401
        
        app.logger.info('OTPProvider: Token Expiration Looks Good! ')
        app.logger.info('OTPProvider: Token is valid!')
        
        # Token is valid
        data = generate_totp(otp_key.encode())
        app.logger.info('OTPProvider: Return data to client!')
        app.logger.info('OTPProvider: Closing connection')
        return jsonify({'data': data}), 200
        
    except jwt.InvalidTokenError as e:
        print(e)

        app.logger.error('OTPProvider: Invalid Token: ' + str(e))
        return jsonify({'message': 'Invalid token'}), 401


    
# MS SQL Provider

@app.route('/provider/mssql', methods=['GET'])
def mssql():
    # Get token from request headers
    auth_header = request.headers.get('Authorization')
    token = None
    
    if auth_header:
        app.logger.info('SQLProvider: Got Auth Header '+ auth_header )
        token = auth_header.split(" ")[1]
        app.logger.info('SQLProvider: Got Token '+ token )
    else:
        return render_template("404.html")
    # Check if token exists and is not empty
    if not token:
        app.logger.error('SQLProvider: Token missing')
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        # Decode token and get expiration time
        secret_key = config.get('SECRET_KEY', 'key')
        app.logger.info('SQLProvider: Decoding token')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        expiration_time = decoded.get('exp')
        app.logger.info('SQLProvider: Got Expiration Date '+ str(expiration_time ))
        #Get client name
        client = decoded.get('client')
        app.logger.info('SQLProvider: Got Client '+ str(client) )
        
        
        with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key,sql_query FROM users WHERE username=?", (client,))
                result = cur.fetchone()
                app.logger.info('SQLProvider: Got client key from database ')
                
                if not result:
                    app.logger.error('SQLProvider: User missconfiguration')
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
                sql_query = result[1]
        
        app.logger.info('SQLProvider: Checking if token expired '+ str(datetime.datetime.now().timestamp()) + ' ' + str(expiration_time))
        
        now = datetime.datetime.now()
        app.logger.info(now.strftime("%Y-%m-%d %H:%M:%S"))
        app.logger.info(datetime.datetime.fromtimestamp(expiration_time))
        
        # Check if token is expired
        if datetime.datetime.now().timestamp() > expiration_time:
            app.logger.error('SQLProvider: Token Expired!')
            return jsonify({'message': 'Token expired'}), 401
        
        app.logger.info('SQLProvider: Token Expiration Looks Good! ')
        app.logger.info('SQLProvider: Token is valid!')
        
        # Token is valid
        data = generate_totp(otp_key.encode())
        app.logger.info('SQLProvider: Return data to client!')
        app.logger.info('SQLProvider: Closing connection')
        

        
        # Create an instance of the SqlToJson class
        conn = SqlToJson(config.get(client, 'dbhost').replace("\"", ""), config.get(client, 'username').replace("\"", ""), config.get(client, 'password').replace("\"", ""), config.get(client, 'database').replace("\"", ""))

        # Execute a SQL query and get the results as JSON
        json_results = conn.run_query(format(sql_query))

        # Print the JSON output
        parsed_result = json.loads(json_results)
        print(parsed_result)

        
        return json_results, 200
        
    except jwt.InvalidTokenError as e:
        print(e)

        app.logger.error('SQLProvider: Invalid Token: ' + str(e))
        return jsonify({'message': 'Invalid token'}), 401
    
    
# MYSQL Provider

@app.route('/provider/mysql', methods=['GET'])
def mysql():
    # Get token from request headers
    auth_header = request.headers.get('Authorization')
    token = None
    
    if auth_header:
        app.logger.info('MYSQLProvider: Got Auth Header '+ auth_header )
        token = auth_header.split(" ")[1]
        app.logger.info('MYSQLProvider: Got Token '+ token )
    else:
        return render_template("404.html")
    # Check if token exists and is not empty
    if not token:
        app.logger.error('MYSQLProvider: Token missing')
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        # Decode token and get expiration time
        secret_key = config.get('SECRET_KEY', 'key')
        app.logger.info('MYSQLProvider: Decoding token')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        expiration_time = decoded.get('exp')
        app.logger.info('MYSQLProvider: Got Expiration Date '+ str(expiration_time ))
        #Get client name
        client = decoded.get('client')
        app.logger.info('MYSQLProvider: Got Client '+ str(client) )
        
        
        with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key,sql_query FROM users WHERE username=?", (client,))
                result = cur.fetchone()
                app.logger.info('SQLProvider: Got client key from database ')
                
                if not result:
                    app.logger.error('SQLProvider: User missconfiguration')
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
                sql_query = result[1]
        
        app.logger.info('MYSQLProvider: Checking if token expired '+ str(datetime.datetime.now().timestamp()) + ' ' + str(expiration_time))
        
        now = datetime.datetime.now()
        app.logger.info(now.strftime("%Y-%m-%d %H:%M:%S"))
        app.logger.info(datetime.datetime.fromtimestamp(expiration_time))
        
        # Check if token is expired
        if datetime.datetime.now().timestamp() > expiration_time:
            app.logger.error('MYSQLProvider: Token Expired!')
            return jsonify({'message': 'Token expired'}), 401
        
        app.logger.info('MYSQLProvider: Token Expiration Looks Good! ')
        app.logger.info('MYSQLProvider: Token is valid!')
        
        # Token is valid
        data = generate_totp(otp_key.encode())
        app.logger.info('MYSQLProvider: Return data to client!')
        app.logger.info('MYSQLProvider: Closing connection')
        

        
        # Create an instance of the SqlToJson class
        conn = SqlToJson(config.get(client, 'dbhost').replace("\"", ""), config.get(client, 'username').replace("\"", ""), config.get(client, 'password').replace("\"", ""), config.get(client, 'database').replace("\"", ""))

        # Execute a SQL query and get the results as JSON
        json_results = conn.run_query(format(sql_query))

        # Print the JSON output
        parsed_result = json.loads(json_results)
        print(parsed_result)

        
        return json_results, 200
        
    except jwt.InvalidTokenError as e:
        print(e)

        app.logger.error('MYSQLProvider: Invalid Token: ' + str(e))
        return jsonify({'message': 'Invalid token'}), 401
    
    
# SMS Provider

@app.route('/provider/sms', methods=['GET'])
def sms():
    # Get token from request headers
    auth_header = request.headers.get('Authorization')
    token = None
    
    if auth_header:
        app.logger.info('SMSProvider: Got Auth Header '+ auth_header )
        token = auth_header.split(" ")[1]
        app.logger.info('SMSProvider: Got Token '+ token )
    else:
        return render_template("404.html")
    # Check if token exists and is not empty
    if not token:
        app.logger.error('SMSProvider: Token missing')
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        # Decode token and get expiration time
        secret_key = config.get('SECRET_KEY', 'key')
        app.logger.info('SMSProvider: Decoding token')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        expiration_time = decoded.get('exp')
        app.logger.info('SMSProvider: Got Expiration Date '+ str(expiration_time ))
        #Get client name
        client = decoded.get('client')
        app.logger.info('SMSProvider: Got Client '+ str(client) )
        
        
        with sqlite3.connect(os.path.join(sys.path[0], 'users.db')) as con:
                cur = con.cursor()
                cur.execute("SELECT otp_key,phonenumber FROM users WHERE username=?", (client,))
                result = cur.fetchone()
                app.logger.info('SMSProvider: Got client key from database ')
                
                if not result:
                    app.logger.error('SMSProvider: User missconfiguration')
                    return jsonify({'message': 'User missconfigured'}), 401
                
                otp_key = result[0]
                phone = result[1]
        
        app.logger.info('SMSProvider: Checking if token expired '+ str(datetime.datetime.now().timestamp()) + ' ' + str(expiration_time))
        
        now = datetime.datetime.now()
        app.logger.info(now.strftime("%Y-%m-%d %H:%M:%S"))
        app.logger.info(datetime.datetime.fromtimestamp(expiration_time))
        
        # Check if token is expired
        if datetime.datetime.now().timestamp() > expiration_time:
            app.logger.error('SMSProvider: Token Expired!')
            return jsonify({'message': 'Token expired'}), 401
        
        app.logger.info('SMSProvider: Token Expiration Looks Good! ')
        app.logger.info('SMSProvider: Token is valid!')
        
        # Token is valid
        data = generate_totp(otp_key.encode())
        app.logger.info('SMSProvider: Return data to client!')
        app.logger.info('SMSProvider: Closing connection')
        
        # Send OTP with SMS
        try:
            ssh = RemoteSSH(config.get('SMS_GATEWAY', 'gateway'), 22, config.get('SMS_GATEWAY', 'username'), config.get('SMS_GATEWAY', 'password'))
            result = ssh.send_command('sudo /usr/bin/gammu -c /etc/gammu-smsdrc sendsms TEXT '+str(phone)+' -text '+str(data)+' > /dev/null 2>&1')
            print(result)
        except Exception as e:
            print(e)
        
        return "OK", 200
        
    except jwt.InvalidTokenError as e:
        print(e)

        app.logger.error('SMSProvider: Invalid Token: ' + str(e))
        return jsonify({'message': 'Invalid token'}), 401
    


if __name__ == '__main__':
    app.run(debug=True)



#curl -X POST -u john:password123 http://localhost:5000/login
#curl -X GET http://localhost:5000/protected -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvdHAiOiI0MzU2ODQiLCJleHAiOjE2Nzg5NjA3MjZ9.BXmwfp8afjMMOL-EuQWeWyZq7P4UIX7VfDmHyNaL_aY
#gammu -c /etc/gammu-smsdrc sendsms TEXT 6977456030 -text "'lalakis'"

