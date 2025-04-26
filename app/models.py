from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Text
from datetime import datetime 
from . import db, login_manager


class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False,)
    display_name = db.Column(db.String(20), unique=True, nullable=False,)
    email = db.Column(db.String(120), unique=True, nullable=False,)
    public_key = db.Column(Text, nullable=False)
    private_key = db.Column(Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    image_file = db.Column(db.String(120), nullable=False,
                           default='default.png')
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Message(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    sender_id = db.Column(db.Integer,db.ForeignKey('users.id'),nullable=False)
    recipient_id = db.Column(db.Integer,db.ForeignKey('users.id'),nullable=False)
    body = db.Column(db.Text,nullable=False)
    timestamp = db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    is_read = db.Column(db.Boolean,default=False)

    #Relationships
    sender = db.relationship('users',foreign_keys=[sender_id],backref='sent_messages')
    recipient = db.relationship('users',foreign_keys=[recipient_id],backref='received_messages')
    def __repr__(self):
        return f'<Message {self.id} From {self.sender_id} To {self.recipient_id}>'
@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))
