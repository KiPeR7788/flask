from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore
import os
import hashlib
import uuid

app = Flask(__name__)
CORS(app)

# Конфигурация
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-in-production')
app.config['TOKEN_EXPIRY_MINUTES'] = 30

# Инициализация Firebase
try:
    firebase_config = {
        "type": os.environ.get('FIREBASE_TYPE', 'service_account'),
        "project_id": os.environ.get('FIREBASE_PROJECT_ID', 'your-project-id'),
        "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID', ''),
        "private_key": os.environ.get('FIREBASE_PRIVATE_KEY', '').replace('\\n', '\n'),
        "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL', ''),
        "client_id": os.environ.get('FIREBASE_CLIENT_ID', ''),
        "auth_uri": os.environ.get('FIREBASE_AUTH_URI', 'https://accounts.google.com/o/oauth2/auth'),
        "token_uri": os.environ.get('FIREBASE_TOKEN_URI', 'https://oauth2.googleapis.com/token'),
        "auth_provider_x509_cert_url": os.environ.get('FIREBASE_AUTH_PROVIDER_CERT_URL', 'https://www.googleapis.com/oauth2/v1/certs'),
        "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL', '')
    }
    
    if firebase_config['private_key']:
        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase initialized successfully")
    else:
        raise Exception("Firebase credentials not provided")
        
except Exception as e:
    print(f"❌ Firebase initialization failed: {e}")
    db = None

# Вспомогательные функции
def hash_password(password):
    """Хэширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user_id, username):
    """Генерация JWT токена"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=app.config['TOKEN_EXPIRY_MINUTES'])
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """Декоратор для проверки JWT токена"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({
                'status': 'error', 
                'message': 'Token is missing!'
            }), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['user_id']
            request.current_user = current_user
            request.user_data = data
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 'error', 
                'message': 'Token has expired!'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'status': 'error', 
                'message': 'Token is invalid!'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Маршруты API
@app.route("/")
def home():
    return jsonify({
        "status": "success",
        "message": "GameZY Server is running! 🚀",
        "version": "1.0.0",
        "endpoints": {
            "register": "POST /register",
            "login": "POST /login", 
            "verify_token": "POST /verify-token",
            "refresh_token": "POST /refresh-token",
            "user_profile": "GET /profile",
            "health": "GET /health"
        }
    })

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "success",
        "message": "Server is healthy ✅",
        "timestamp": datetime.datetime.now().isoformat(),
        "firebase_status": "connected" if db else "disconnected"
    })

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error", 
                "message": "No JSON data provided"
            }), 400
            
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "").strip()
        
        # Валидация данных
        if not all([username, email, password]):
            return jsonify({
                "status": "error", 
                "message": "Все поля обязательны для заполнения"
            }), 400
        
        if len(username) < 3:
            return jsonify({
                "status": "error",
                "message": "Имя пользователя должно содержать минимум 3 символа"
            }), 400
            
        if len(password) < 6:
            return jsonify({
                "status": "error",
                "message": "Пароль должен содержать минимум 6 символов"
            }), 400
        
        # Проверка существования пользователя
        users_ref = db.collection('users')
        
        # Проверка email
        email_query = users_ref.where('email', '==', email).limit(1)
        existing_email = email_query.get()
        
        if len(existing_email) > 0:
            return jsonify({
                "status": "error", 
                "message": "Пользователь с таким email уже существует"
            }), 400
        
        # Проверка username
        username_query = users_ref.where('username', '==', username).limit(1)
        existing_username = username_query.get()
        
        if len(existing_username) > 0:
            return jsonify({
                "status": "error", 
                "message": "Пользователь с таким именем уже существует"
            }), 400
        
        # Создание нового пользователя
        user_id = str(uuid.uuid4())
        hashed_password = hash_password(password)
        current_time = datetime.datetime.now()
        
        user_data = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'password_hash': hashed_password,
            'email_verified': False,
            'created_at': current_time,
            'last_login': current_time,
            'is_online': False,
            'avatar_url': '',
            'bio': '',
            'followers_count': 0,
            'following_count': 0,
            'friends_count': 0,
            'level': 1,
            'experience': 0,
            'coins': 100  # Начальные монеты
        }
        
        # Сохранение в Firestore
        users_ref.document(user_id).set(user_data)
        
        # Генерация токена
        token = generate_token(user_id, username)
        
        print(f"✅ Новый пользователь зарегистрирован: {username} ({email})")
        
        return jsonify({
            "status": "success",
            "message": "Пользователь успешно зарегистрирован",
            "token": token,
            "user_id": user_id,
            "username": username,
            "email": email,
            "token_expires_in": f"{app.config['TOKEN_EXPIRY_MINUTES']} minutes"
        }), 201
        
    except Exception as e:
        print(f"❌ Ошибка регистрации: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Внутренняя ошибка сервера: {str(e)}"
        }), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error", 
                "message": "No JSON data provided"
            }), 400
            
        email = data.get("email", "").strip().lower()
        password = data.get("password", "").strip()
        
        if not all([email, password]):
            return jsonify({
                "status": "error", 
                "message": "Email и пароль обязательны"
            }), 400
        
        # Поиск пользователя
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1)
        user_docs = query.get()
        
        if len(user_docs) == 0:
            return jsonify({
                "status": "error", 
                "message": "Неверный email или пароль"
            }), 401
        
        user_doc = user_docs[0]
        user_data = user_doc.to_dict()
        
        # Проверка пароля
        hashed_password = hash_password(password)
        if user_data.get('password_hash') != hashed_password:
            return jsonify({
                "status": "error", 
                "message": "Неверный email или пароль"
            }), 401
        
        # Проверка верификации email
        if not user_data.get('email_verified', False):
            return jsonify({
                "status": "error",
                "message": "Email не подтвержден. Проверьте вашу почту."
            }), 403
        
        # Обновление времени последнего входа
        users_ref.document(user_doc.id).update({
            'last_login': datetime.datetime.now(),
            'is_online': True
        })
        
        # Генерация токена
        token = generate_token(user_doc.id, user_data['username'])
        
        print(f"✅ Успешный вход: {user_data['username']} ({email})")
        
        return jsonify({
            "status": "success",
            "message": "Вход выполнен успешно",
            "token": token,
            "user_id": user_doc.id,
            "username": user_data['username'],
            "email": user_data['email'],
            "avatar_url": user_data.get('avatar_url', ''),
            "level": user_data.get('level', 1),
            "coins": user_data.get('coins', 0),
            "token_expires_in": f"{app.config['TOKEN_EXPIRY_MINUTES']} minutes"
        }), 200
        
    except Exception as e:
        print(f"❌ Ошибка входа: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Внутренняя ошибка сервера: {str(e)}"
        }), 500

@app.route("/verify-token", methods=["POST"])
@token_required
def verify_token():
    """Проверка валидности токена"""
    return jsonify({
        "status": "success",
        "message": "Token is valid",
        "user_id": request.user_data['user_id'],
        "username": request.user_data['username'],
        "expires_at": datetime.datetime.fromtimestamp(request.user_data['exp']).isoformat()
    }), 200

@app.route("/refresh-token", methods=["POST"])
@token_required
def refresh_token():
    """Обновление токена"""
    try:
        users_ref = db.collection('users')
        user_doc = users_ref.document(request.current_user).get()
        
        if not user_doc.exists:
            return jsonify({
                "status": "error",
                "message": "User not found"
            }), 404
            
        user_data = user_doc.to_dict()
        
        # Генерация нового токена
        new_token = generate_token(request.current_user, user_data['username'])
        
        return jsonify({
            "status": "success",
            "message": "Token refreshed successfully",
            "token": new_token,
            "user_id": request.current_user,
            "username": user_data['username'],
            "token_expires_in": f"{app.config['TOKEN_EXPIRY_MINUTES']} minutes"
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error refreshing token: {str(e)}"
        }), 500

@app.route("/profile", methods=["GET"])
@token_required
def get_profile():
    """Получение профиля пользователя"""
    try:
        users_ref = db.collection('users')
        user_doc = users_ref.document(request.current_user).get()
        
        if not user_doc.exists:
            return jsonify({
                "status": "error",
                "message": "User not found"
            }), 404
            
        user_data = user_doc.to_dict()
        
        # Возвращаем профиль без чувствительных данных
        profile = {
            "user_id": user_data.get('user_id'),
            "username": user_data.get('username'),
            "email": user_data.get('email'),
            "avatar_url": user_data.get('avatar_url', ''),
            "bio": user_data.get('bio', ''),
            "level": user_data.get('level', 1),
            "experience": user_data.get('experience', 0),
            "coins": user_data.get('coins', 0),
            "followers_count": user_data.get('followers_count', 0),
            "following_count": user_data.get('following_count', 0),
            "friends_count": user_data.get('friends_count', 0),
            "created_at": user_data.get('created_at').isoformat() if user_data.get('created_at') else None,
            "last_login": user_data.get('last_login').isoformat() if user_data.get('last_login') else None,
            "is_online": user_data.get('is_online', False)
        }
        
        return jsonify({
            "status": "success",
            "message": "Profile retrieved successfully",
            "profile": profile
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving profile: {str(e)}"
        }), 500

@app.route("/logout", methods=["POST"])
@token_required
def logout():
    """Выход пользователя"""
    try:
        users_ref = db.collection('users')
        users_ref.document(request.current_user).update({
            'is_online': False,
            'last_logout': datetime.datetime.now()
        })
        
        return jsonify({
            "status": "success",
            "message": "Logged out successfully"
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error during logout: {str(e)}"
        }), 500

# Обработка ошибок
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    print(f"🚀 Starting GameZY Server on port {port}")
    print(f"🔑 Token expiry: {app.config['TOKEN_EXPIRY_MINUTES']} minutes")
    print(f"🐛 Debug mode: {debug}")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
