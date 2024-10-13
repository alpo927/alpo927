from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Kendi gizli anahtarını değiştir
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Kendi gizli anahtarını değiştir
db = SQLAlchemy(app)
jwt = JWTManager(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    def __repr__(self):
        return f'<User {self.username}>'
class AdView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_earned = db.Column(db.Float, nullable=False)
    def __repr__(self):
        return f'<AdView {self.id}>'
db.create_all()  # Database tablosunu oluştur
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401
@app.route('/watch_ad', methods=['POST'])
@jwt_required()
def watch_ad():
    user_id = get_jwt_identity()
    ad_value = 0.1
    user = User.query.get(user_id)
    user.balance += ad_value
    new_ad_view = AdView(user_id=user_id, amount_earned=ad_value)
    db.session.add(new_ad_view)
    db.session.commit()
    return jsonify({'message': 'Ad watched successfully', 'new_balance': user.balance}), 200
@app.route('/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    min_withdraw_amount = 10.0
    if user.balance >= min_withdraw_amount:
        user.balance = 0
        db.session.commit()
        return jsonify({'message': 'Withdrawal successful'}), 200
    return jsonify({'message': 'Insufficient balance for withdrawal'}), 400
if __name__ == '__main__':
    app.run(debug=True)- 👋 Hi, I’m @alpo927
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...

<!---
alpo927/alpo927 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
