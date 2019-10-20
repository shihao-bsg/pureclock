from flask_wtf import Form
from wtforms.fields import StringField, PasswordField, BooleanField, SubmitField, SelectField, DateField
from wtforms.fields.html5 import DateField
from flask_wtf.html5 import URLField
from wtforms.validators import DataRequired, url, Length, Email, Regexp, EqualTo, ValidationError

from models import User


class BookmarkForm(Form):
	task = StringField('Your Task:', validators=[DataRequired()])
	company = StringField('Company Name:', validators=[DataRequired()])
	workdate = DateField("Date :", validators=[DataRequired()])
	time = StringField('Working Time', validators=[DataRequired()])
	description = StringField('Add an optional description:')
	
	def validate(self):
		#if not self.url.data.startswith("http://") or\
		#	self.url.data.startswith("https://"):
		#	self.url.data="http://"+self.url.data
		if not Form.validate(self):
			return False
		if not self.description.data:
			self.description.data = self.task.data
		return True


class LoginForm(Form):
	username = StringField('Your Username:', validators=[DataRequired()])
	password = PasswordField('Password:', validators=[DataRequired()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('log In')


class SetUsernameForm(Form):
    username = StringField('Username:', validators=[DataRequired(), Length(3, 80), Regexp('^[A-Za-z0-9_]{3,}$', message='Usernames consist of numbers, letters, and underscores.')])
    password = PasswordField('Password:', validators=[DataRequired(), EqualTo('password2', message='Password must match.')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register', validators=[DataRequired()])


class SignupForm(Form):
    username = StringField('Username:', validators=[DataRequired(), Length(3, 80), Regexp('^[A-Za-z0-9_]{3,}$', message='Usernames consist of numbers, letters, and underscores.')])
    password = PasswordField('Password:', validators=[DataRequired(), EqualTo('password2', message='Password must match.')])
    password2 = PasswordField('Confirm Password', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Length(1, 120), Email()])
    def validate_email(self, email_field):
        if User.query.filter_by(email=email_field.data).first():
            raise ValidationError('There already is a user with this email')
    def validate_username(self, username_field):
        if User.query.filter_by(username=username_field.data).first():
            raise ValidationError('This username is already taken')