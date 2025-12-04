from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, UserMixin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///saas.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['USER_ENABLE_EMAIL'] = False

# Initialize database
db = SQLAlchemy(app)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, nullable=False, server_default='1')
    roles = db.relationship('Role', secondary='user_roles')

# Role model
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

# UserRoles association table
class UserRoles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'))

# Create database tables
db.create_all()

# Setup Flask-User
user_manager = UserManager(app, db, User)

if __name__ == '__main__':
    app.run(debug=True)
