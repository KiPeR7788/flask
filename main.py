from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
import os
import hashlib
import uuid
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Конфигурация
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-123')
app.config['TOKEN_EXPIRY_MINUTES'] = 30

# In-memory хранилище для демо (в продакшене используйте базу данных)
users_storage = {}
games_storage = {}

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
            request.current_user = data['user_id']
            request.user_data = data
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 'error', 
                'message': 'Token has expired!'
            }), 401
        except jwt.InvalidTokenError as e:
            return jsonify({
                'status': 'error', 
                'message': f'Token is invalid: {str(e)}'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Маршруты API
@app.route("/")
def home():
    return jsonify({
        "status": "success",
        "message": "🎮 GameZY Server is running!",
        "version": "1.0.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "mode": "in-memory",
        "endpoints": {
            "register": "POST /register",
            "login": "POST /login", 
            "verify_token": "POST /verify-token",
            "user_profile": "GET /profile",
            "health": "GET /health",
            "games": "GET /games"
        }
    })

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "success",
        "message": "✅ Server is healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "users_count": len(users_storage),
        "port": os.environ.get('PORT', '5000')
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
        for user_id, user_data in users_storage.items():
            if user_data['email'] == email:
                return jsonify({
                    "status": "error", 
                    "message": "Пользователь с таким email уже существует"
                }), 400
            if user_data['username'] == username:
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
            'email_verified': True,  # Для демо сразу верифицирован
            'created_at': current_time,
            'last_login': current_time,
            'is_online': True,
            'avatar_url': '',
            'bio': 'Новый игрок GameZY 🎮',
            'followers_count': 0,
            'following_count': 0,
            'friends_count': 0,
            'level': 1,
            'experience': 0,
            'coins': 1000,
            'games_played': 0,
            'games_won': 0,
            'achievements': ['Новичок']
        }
        
        # Сохранение пользователя
        users_storage[user_id] = user_data
        
        # Генерация токена
        token = generate_token(user_id, username)
        
        logger.info(f"✅ Новый пользователь: {username} ({email})")
        
        return jsonify({
            "status": "success",
            "message": "🎉 Регистрация успешна! Добро пожаловать в GameZY!",
            "token": token,
            "user_id": user_id,
            "username": username,
            "email": email,
            "level": 1,
            "coins": 1000,
            "token_expires_in": f"{app.config['TOKEN_EXPIRY_MINUTES']} минут"
        }), 201
        
    except Exception as e:
        logger.error(f"❌ Ошибка регистрации: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": "Произошла ошибка при регистрации"
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
        user_found = None
        for user_id, user_data in users_storage.items():
            if user_data['email'] == email:
                user_found = user_data
                break
        
        if not user_found:
            return jsonify({
                "status": "error", 
                "message": "Пользователь не найден"
            }), 401
        
        # Проверка пароля
        hashed_password = hash_password(password)
        if user_found['password_hash'] != hashed_password:
            return jsonify({
                "status": "error", 
                "message": "Неверный пароль"
            }), 401
        
        # Обновление времени входа
        user_found['last_login'] = datetime.datetime.now()
        user_found['is_online'] = True
        
        # Генерация токена
        token = generate_token(user_found['user_id'], user_found['username'])
        
        logger.info(f"✅ Успешный вход: {user_found['username']}")
        
        return jsonify({
            "status": "success",
            "message": f"👋 Добро пожаловать, {user_found['username']}!",
            "token": token,
            "user_id": user_found['user_id'],
            "username": user_found['username'],
            "email": user_found['email'],
            "avatar_url": user_found['avatar_url'],
            "level": user_found['level'],
            "coins": user_found['coins'],
            "experience": user_found['experience'],
            "token_expires_in": f"{app.config['TOKEN_EXPIRY_MINUTES']} минут"
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Ошибка входа: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": "Ошибка при входе в систему"
        }), 500

@app.route("/verify-token", methods=["POST"])
@token_required
def verify_token():
    """Проверка валидности токена"""
    user_data = users_storage.get(request.current_user)
    if not user_data:
        return jsonify({
            "status": "error",
            "message": "User not found"
        }), 404
        
    return jsonify({
        "status": "success",
        "message": "✅ Token is valid",
        "user_id": request.user_data['user_id'],
        "username": request.user_data['username'],
        "expires_at": datetime.datetime.fromtimestamp(request.user_data['exp']).isoformat()
    }), 200

@app.route("/profile", methods=["GET"])
@token_required
def get_profile():
    """Получение профиля пользователя"""
    try:
        user_data = users_storage.get(request.current_user)
        if not user_data:
            return jsonify({
                "status": "error",
                "message": "Пользователь не найден"
            }), 404
        
        profile = {
            "user_id": user_data['user_id'],
            "username": user_data['username'],
            "email": user_data['email'],
            "avatar_url": user_data['avatar_url'],
            "bio": user_data['bio'],
            "level": user_data['level'],
            "experience": user_data['experience'],
            "coins": user_data['coins'],
            "followers_count": user_data['followers_count'],
            "following_count": user_data['following_count'],
            "friends_count": user_data['friends_count'],
            "games_played": user_data['games_played'],
            "games_won": user_data['games_won'],
            "achievements": user_data['achievements'],
            "created_at": user_data['created_at'].isoformat(),
            "last_login": user_data['last_login'].isoformat(),
            "is_online": user_data['is_online']
        }
        
        return jsonify({
            "status": "success",
            "message": "Профиль загружен",
            "profile": profile
        }), 200
        
    except Exception as e:
        logger.error(f"❌ Ошибка получения профиля: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Ошибка загрузки профиля"
        }), 500

@app.route("/games", methods=["GET"])
def get_games():
    """Получение списка игр"""
    games = [
        {
            "id": 1,
            "name": "⚔️ Battle Royale",
            "description": "Сражайся до последнего выжившего",
            "players_online": 150,
            "max_players": 100,
            "difficulty": "hard"
        },
        {
            "id": 2, 
            "name": "🎯 Archery Challenge",
            "description": "Попади в цель и стань лучшим стрелком",
            "players_online": 75,
            "max_players": 50,
            "difficulty": "medium"
        },
        {
            "id": 3,
            "name": "🏎️ Racing Extreme", 
            "description": "Гонки на выживание",
            "players_online": 200,
            "max_players": 8,
            "difficulty": "easy"
        },
        {
            "id": 4,
            "name": "🧩 Puzzle Master",
            "description": "Испытай свой интеллект",
            "players_online": 45,
            "max_players": 2,
            "difficulty": "medium"
        }
    ]
    
    return jsonify({
        "status": "success",
        "games": games,
        "total_games": len(games)
    })

@app.route("/leaderboard", methods=["GET"])
def get_leaderboard():
    """Таблица лидеров"""
    leaders = []
    for user_id, user_data in users_storage.items():
        leaders.append({
            "username": user_data['username'],
            "level": user_data['level'],
            "experience": user_data['experience'],
            "coins": user_data['coins'],
            "games_won": user_data['games_won']
        })
    
    # Сортировка по уровню и опыту
    leaders.sort(key=lambda x: (-x['level'], -x['experience']))
    
    return jsonify({
        "status": "success",
        "leaderboard": leaders[:10],  # Топ-10
        "updated_at": datetime.datetime.now().isoformat()
    })

# Обработка ошибок
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "🚫 Endpoint not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "status": "error",
        "message": "💥 Internal server error"
    }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"🚀 Starting GameZY Server on port {port}")
    logger.info(f"🔑 Token expiry: {app.config['TOKEN_EXPIRY_MINUTES']} minutes")
    logger.info(f"🐛 Debug mode: {debug}")
    
    # Добавляем тестового пользователя
    test_user_id = str(uuid.uuid4())
    users_storage[test_user_id] = {
        'user_id': test_user_id,
        'username': 'demo_user',
        'email': 'demo@gamezy.com',
        'password_hash': hash_password('123456'),
        'email_verified': True,
        'created_at': datetime.datetime.now(),
        'last_login': datetime.datetime.now(),
        'is_online': True,
        'avatar_url': '',
        'bio': 'Тестовый игрок',
        'followers_count': 10,
        'following_count': 5,
        'friends_count': 3,
        'level': 5,
        'experience': 1250,
        'coins': 2500,
        'games_played': 25,
        'games_won': 15,
        'achievements': ['Новичок', 'Победитель', 'Легенда']
    }
    
    logger.info("✅ Demo user created: demo@gamezy.com / 123456")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
