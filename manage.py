from flask import Flask, request, jsonify, render_template, redirect, url_for, abort
import uuid
import jwt
import datetime
from functools import wraps
from user_model import UserModel
import re
import md5

app = Flask(__name__)
app.config['SECRET_KEY']='secret_key'
domain = '0.0.0.0'
port = 8001

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        print "TOKEN REQUIRED"
        phone = kwargs['data'] 
        if not phone:
            phone = request.json.get('phone')
        user_model_obj = UserModel()
        user = user_model_obj.get(phone)
        token = user['access_token']
        if not token:  
            return jsonify({'message': 'a valid token is missing'})  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = UserModel().get(data['phone'])
        except:
             return jsonify({'message': 'token is invalid'}) 
        return f(current_user)
    return wrapper


def verify_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        #token = kwargs['data']
        print args
        token = request.json.get('token')
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            #current_user = 'valid token'
        except:
            return jsonify({'message': 'token is invalid'}) 
        return f()
    return wrapper

@app.route('/register', methods=['POST'])
def register(): 
    """
    direct call
    """
    password = str(request.json.get('password'))
    phone = str(request.json.get('phone'))
    if not phone or not password:
        #abort(400) #phone or password not given
        return jsonify({'error':'phone/password error'})
    if not __check_phone_number(phone):
        print 'wrong phone number'
        #abort(400) #phone number is wrong format #return 'Phone Number Incorrect'
        return jsonify({'error':'phone number error'})
    #has password
    hashed_password = md5.md5(password).hexdigest()
    #init data
    new_user = {
            'phone':phone,
            'password':hashed_password,
            'openid': str(uuid.uuid4()),
            }
    #set to database
    user_model_obj = UserModel()
    user_model_obj.set(phone,new_user)
    
    #return (jsonify({'phone': phone}), 201,{'Location': url_for('get_user', id=phone, _external=True)})
    return redirect(url_for('get_user',id=phone))

@app.route('/user/<int:id>')
def get_user(id):
    """
    used for redirect not for direct call
    """
    user = UserModel().get(id)
    if not user:
        #abort(400)
        return jsonify({'error':'user error'})
    return jsonify({'phone': user['phone']})


@app.route('/login', methods=['POST'])  
def login_user():
    """
    issue the user a new access token
    direct call
    """
    password = str(request.json.get('password'))
    phone = str(request.json.get('phone'))
    
    if phone is None or password is None:
        #phone or password not submitted
        jsonify({"error":"Enter Phone Number and Password "}) 
    
    user_model_obj = UserModel()
    user = user_model_obj.get(phone)
    if user is None:
        #no user with that phone number
        return jsonify({"error":"Phone Number and/or Password is incorrect"})  
        
    #if there is a user with that phone number and the password is correct   
    if user and verify_password(user['password'], password):
        #check if the user has an access_token 
        if 'access_token' in user:
            try:
                #check if access_token is still valid
                data = jwt.decode(user['access_token'], app.config['SECRET_KEY'])
                token = user['access_token']
            except:
                #if not valid issue new token
                token = jwt.encode({'phone': user['phone'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        else:
            #if user doesn't have a token issue a token
            token = jwt.encode({'phone': user['phone'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        #update the users data with the token
        user['access_token'] = token
        user_model_obj.set(user['phone'], user)
    else:
        return jsonify({"error":"Username and/or Password is incorrect"})
    print "REDIRECT"
    #return (jsonify({'phone': phone}), 201,{'Location': url_for('get_profile', data=token, _external=True)})
    return redirect(url_for('get_profile',data=phone))


@app.route('/api/profile/<data>', methods=['GET', 'POST'])
@token_required
def get_profile(current_user):
    """
    redirect not for direct call
    """
    print "GET PROFILE"
    return jsonify({'current_user': current_user})


@app.route('/api/data/', methods=['GET', 'POST'])
@verify_token
def get_data():
    """
    direct call
    """
    return jsonify({'data': 'data'})


@app.route('/users', methods=['GET'])
def get_all_users():  
    """
    direct call
    """
    user_model_obj = UserModel()
    users = user_model_obj.keys()
    result = []   
    user_data = {}
    for user in users:   
        user_data.update({user:user_model_obj.get(user)}) 
    result.append(user_data)   
    return jsonify({'users': result})


def __check_phone_number(phone):
    phone = str(phone)
    pre = re.compile('^0\d{2,3}\d{7,8}$|^1[23456789]\d{9}$|^147\d{8}')
    phonematch = pre.match(phone) 
    if phonematch:
        return True
    return False


def verify_password(user_pass,password):
    password = md5.md5(password).hexdigest()
    if user_pass != password:
        return False
    return True


app.run(host=domain,port=port,debug=True)