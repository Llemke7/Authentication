
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

db = SQLAlchemy()

class User(db.Model):
    username = db.Column(db.String(20), primary_key=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text(50), nullable=False, unique=True)
    first_name = db.Column(db.Text(30), nullable=False)
    last_name = db.Column(db.Text(30), nullable=False)

class Registration(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=50)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=30)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=30)])
    submit = SubmitField('Register')

class Login(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class Feedback(db.Model):
    id = db.Column(db.Integer, autoincrement = True, primary_key = True)
    title = db.Column(db.String(100), nullable = False)
    content = db.Column(db.Text, nullable = False)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable = False)