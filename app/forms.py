from flask.ext.wtf import Form
from wtforms import StringField, BooleanField, DateField, TextField
from wtforms.validators import DataRequired, Email, Length, Optional
from wtforms.widgets import TextArea


class BasicForm(Form):
	user_name = StringField('user_name', validators=[DataRequired(), Length(max=24)])
	user_pass = StringField('user_pass', validators=[DataRequired(), Length(max=128)])

class LoginForm(BasicForm):
  remember_me = BooleanField('remember_me', default=False)

class RegisterForm(BasicForm):
	password_confirmation = StringField('password_confirmation', validators=[DataRequired(), Length(max=128)])
	pass

class RequestForm(Form):
	request = StringField('request', validators=[DataRequired(), Length(max=140)])
	anonymous = BooleanField('anonymous', default=True)
	tweet = BooleanField('tweet', default=False)

class SettingsForm(Form):
	display_name = StringField('display_name', validators=[Length(max=64)])
	profile_id = StringField('profile_id', validators=[Length(max=24)])
	user_email = StringField('user_email', validators=[Length(max=120)])
	user_pass = StringField('user_pass', validators=[Length(max=128)])
	user_pass_verify = StringField('user_pass_verify', validators=[Length(max=128)])

class EventForm(Form):
	event_name = StringField('event_name', validators=[DataRequired(), Length(max=128)])
	event_desc = StringField('event_desc', validators=[DataRequired(), Length(max=500)])
	pub_event = BooleanField('pub_event', default=True)
	event_id = StringField('event_id', validators=[DataRequired(), Length(max=20)])
	event_date = StringField('event_date', validators=[DataRequired(), Length(min=10, max=10)])
	discussion = StringField('discussion', widget=TextArea())

class EventSettings(Form):
	event_name = StringField('event_name')
	event_desc = StringField('event_desc')
	event_date = StringField('event_date')
	event_address = StringField('event_address')
	event_public = BooleanField('event_public')
	event_complete = BooleanField('event_complete')
	volunteer_schedule = TextField('volunteer_schedule')
	volunteer_schedule_2 = TextField('volunteer_schedule_2')
	volunteer_schedule_3 = TextField('volunteer_schedule_3')
	volunteer_schedule_4 = TextField('volunteer_schedule_4')
	volunteer_schedule_5 = TextField('volunteer_schedule_5')
	volunteer_schedule_6 = TextField('volunteer_schedule_6')
	volunteer_schedule_7 = TextField('volunteer_schedule_7')

class TwitterSettings(Form):
	consumer_key = StringField('consumer_key')
	consumer_secret = StringField('consumer_secret')
	access_token = StringField('access_token')
	access_token_secret = StringField('access_token_secret')

class EventDeleteConfirm(Form):
	confirmation = StringField('confirmation', validators=[Length(min=3, max=3)])

class ContactForm(Form):
	phone_number = StringField('phone_number')
	home_address = StringField('home_address')
	visible = BooleanField('visible')

class TicketForm(Form):
	correspondence = StringField('correspondence', widget=TextArea())
	merge = StringField('merge', widget=TextArea())

class SearchForm(Form):
	search = StringField('search')