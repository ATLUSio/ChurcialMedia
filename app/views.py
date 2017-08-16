from flask import render_template, flash, redirect, jsonify, request, session, url_for, g, Markup, abort
from flask.ext.login import login_user, logout_user, current_user, login_required
from datetime import datetime
from app import app, db, lm
from .models import *
from .forms import *
from random import randint
from config import SWEAR_LIST
import json
import twitter
import hashlib, binascii
from passlib.hash import pbkdf2_sha256

@lm.user_loader
def load_user(id):
	return User.query.get(int(id))

@app.route('/')
@app.route('/index')
def index():
	if 'user' in session:
		user = User.query.filter_by(user_name=session['user']).first()
		requests = []
		if not user.friends:
			requests = Request.query.order_by('id desc').limit(10).all()
		else:
			friends_ids = [user.id]
			for friend in user.friends:
				friends_ids.append(friend.id)
			latest_request = Request.query.order_by('id desc').limit(1).all()
			for request in latest_request:
				lr_id = request.id
			while len(requests) < 10:
				if lr_id == 1:
					requests.append(Request.query.get(lr_id))
					break
				else:
					request = Request.query.get(lr_id)
					if request.parishioner_id in friends_ids:
						requests.append(request)
					lr_id -= 1
		if 'new_user' in session:
			flash(Markup('<h4>Thank you for registering on AdoreJes.us! Please visit your profile to edit your profile information and to submit your first prayer request!</h4>'))
			session.pop('new_user', None)
		if 'ticket_back' in session:
			session.pop('ticket_back', None)
		if user.display_name:
			display = user.display_name
		else:
			display = user.user_name
		return render_template('index.html',
								title='Home',
								requests=requests,
								user=user,
								display=display)
	else:
		return render_template('index.html',
								title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
	if 'user' in session:
		flash('You\'re already logged in, as \'{}\' silly!'.format(session['user']))
		return redirect('/index')
	form = LoginForm()
	if 'failed_logins' in session:
		if session['failed_logins'] > 2:
			flash(Markup('<p style="color: red;">Please use the forgot password feature if you are unable to remember your password or <a href="/register">create one here</a> if you don\'t have one!</p>'))
	if form.validate_on_submit():
		user = User.query.filter_by(user_name=form.user_name.data).first()
		if user and (pbkdf2_sha256.verify(form.user_pass.data, user.password)):
			user.authenticated = True
			login_user(user, remember=True)
			session['display_name'] = user.display_name
			session['user'] = user.user_name
			if user.administrator:
				session['administrator'] = user.administrator
			if 'failed_logins' in session:
				session.pop('failed_logins', None)
			return redirect('/index')
		else:
			flash(Markup('<p style="color: red;">Incorrect username and/or password. Please try again.</p>'))
			if 'failed_logins' not in session:
				session['failed_logins'] = 1
			else:
				session['failed_logins'] += 1
			return redirect('/login')
	return render_template('login.html',
							title='Sign In',
							form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
	if 'user' in session:
		flash('Do not need to register, as you already have an account. :)')
		return redirect(url_for('index'))
	form = RegisterForm()
	if form.validate_on_submit():
		if User.query.filter_by(user_name=form.user_name.data).first() == None:
			if form.user_pass.data == form.password_confirmation.data:
				user = User(
					user_name=form.user_name.data,
					password=pbkdf2_sha256.encrypt(form.user_pass.data, rounds=250000, salt_size=16),
					private_contact=True,
					administrator=False
				)
				try:
					db.session.add(user)
					db.session.commit()
					user.authenticated = True
					login_user(user, remember=True)
					session['user'] = user.user_name
					session['new_user'] = True
					if 'failed_logins'in session:
						session.pop('failed_logins', None)
					return redirect(url_for('index'))
				except:
					flash(Markup('<p style="color: red;">Error signing up with that username and password combination. Please try again.</p>'))
					return redirect('/register')
				db.session.close()
			else:
				flash('Passwords don\'t appear to match. Please re-enter information.')
				return redirect(url_for('register'))
		else:
			flash(Markup('<p style="color: red;">User already registered. Please select a different username. If this is you, <a href="/login">click here to login</a>.</p>'))
			return redirect(url_for('register'))
	return render_template('register.html',
							title='Register',
							form=form)

@app.route('/profile/settings', methods=['GET', 'POST'])
@login_required
def prof_settings():
	form = SettingsForm()
	changed = []
	user = User.query.filter_by(user_name=session['user']).first()
	if form.validate_on_submit():
		if form.display_name.data:
			if form.display_name.data != user.display_name:
				user.display_name = form.display_name.data
				changed.append('Display Name')
		if form.profile_id.data:
			if not user.display_name:
				flash('Please enter in a Display Name before choosing a Profile ID')
				return redirect(url_for('prof_settings'))
			if (User.query.filter_by(profile_id=form.profile_id.data).first() == None):
				if len(form.profile_id.data) > 2:
					user.profile_id = form.profile_id.data
					changed.append('Profile ID')
				else:
					flash(Markup('<p style="color: red;">Please enter a Profile ID that is at least 3 characters long.</p>'))
					changed.append(False)
			elif user.profile_id == form.profile_id.data:
				pass
			else:
				flash(Markup('<p style="color: red;">Desired Profile ID already exists. Please choose a different one.</p>'))
				changed.append(False)
		if form.user_email.data:
			if User.query.filter_by(email=form.user_email.data).first() == None:
				user.email = form.user_email.data
				changed.append('e-Mail')
			elif user.email == form.user_email.data:
				pass
			else:
				flash(Markup('<p style="color: red;">Desired e-Mail already exists. Please verify that you do not already have an account with us.</p>'))
				changed.append(False)
		if form.user_pass.data:
			pass
		if len(changed) > 0:
			if changed[0] == False:
				pass # don't save any fields 
			else:
				db.session.add(user)
				db.session.commit()
				if False in changed:
					changed.remove(False)
					flash("Successfully changed: {}".format(changed))
				else:
					flash("Successfully changed: {}".format(changed))
		else:
			flash("Doesn't appear that anything was to be changed.")
		return redirect(url_for('prof_settings'))
	return render_template('settings_profile.html', title='Settings', form=form, user=user)

@app.route('/api/moderator/<profile_id>', methods=['GET'])
@login_required
def make_mod(profile_id):
	admin = User.query.filter_by(user_name=session['user']).first()
	user = User.query.filter_by(profile_id=profile_id).first()
	if not admin.administrator:
		redirect(url_for('index'))
	if user.moderator:
		user.moderator = False
	else:
		user.moderator = True
	try:
		db.session.add(user)
		db.session.commit()
		if user.moderator:
			flash("Successfully promoted {} to moderator".format(user.user_name))
		else:
			flash("Successfully demoted {} from moderator".format(user.user_name))
	except Exception as e:
		flash('Error making moderator. Error: {}'.format(e))
	return redirect(url_for('get_profile', profile_id=profile_id))

@app.route('/api/requests/delete/<request_id>', methods=['GET'])
@login_required
def delete_request(request_id):
	request = Request.query.get(int(request_id))
	p_id = request.parishioner_id
	user = User.query.filter_by(user_name=session['user']).first()
	if (request and (p_id == user.id)) or user.administrator == True:
		if request.tweet_id:
			try:
				import twitter
				api = twitter.Api(consumer_key=user.twitter_consumer_key,
													consumer_secret=user.twitter_consumer_secret,
													access_token_key=user.twitter_access_token,
													access_token_secret=user.twitter_access_token_secret)
				api.DestroyStatus(request.tweet_id)
			except:
				flash('Error encountered deleting this request from Twitter.')
		db.session.delete(request)
		if ('report' in session) and (session['report'] == True):
			session.pop('report', None)
			report = Report.query.filter_by(request_id=request_id).first()
			db.session.delete(report)
			notification = Notification(parishioner=request.parishioner, body="Your request <{}> was deleted due excessive reports.".format(request.body), type="deletes")
			db.session.add(notification)
			try:
				db.session.commit()
				flash("Successfully deleted request and corresponding report, and notified requester of deletion.")
			except:
				flash("Error in deleting request, report and/or notifying requester of deletion.")
			return redirect(url_for('administration'))
		db.session.commit()
		flash("Successfully deleted this request!")
		return redirect(url_for('profile'))
	elif p_id != user.id:
		flash(Markup("<p style='color: red;'>You're not allowed to do that!</p>"))
		return redirect(url_for('profile'))
	else:
		flash("Error encountered deleting this request.")
		return redirect(url_for('profile'))

@app.route('/api/requests/report/<request_id>', methods=['GET'])
@login_required
def report_request(request_id):
	flash('We are sorry this request offended you in some way. We are looking into this request, and if it is in fact offensive we will remove it immediately. Thank you for your report.')
	user=User.query.filter_by(user_name=session['user']).first()
	report_check = Report.query.filter_by(request_id=request_id).all()
	if len(report_check) > 0:
		report = Report.query.filter_by(request_id=request_id).first()
		reporter_list = (report.reporter_ids).split(', ')
		if str(user.id) not in reporter_list:
			report.reporter_ids = report.reporter_ids + ", {}".format(user.id)
			report.reported_times = int(report.reported_times) + 1
		position = "Duplicate report"
	else:
		report = Report(
			request_id=request_id,
			reporter_ids="{}".format(user.id),
			reported_times=1
			)
		position = "Report creation"
	try:
		db.session.add(report)
		db.session.commit()
	except:
		flash('Encountered error submitting this report. Administration has been notified of your report and the error.')
		report = Report(
			body = position,
			request_id = request_id)
	return redirect(url_for('index'))

@app.route('/api/reports/delete/<report_id>', methods=['GET'])
@login_required
def delete_report(report_id):
	report=Report.query.get(report_id)
	db.session.delete(report)
	db.session.commit()
	flash("Ignored report")
	return redirect(url_for('admin_reports'))

@app.route('/api/logout', methods=['GET', 'POST'])
def logout():
	if 'user' not in session:
		flash("Please login to logout! ;)")
		return redirect(url_for('login'))
	user = User.query.filter_by(user_name=session['user']).first()
	user.authenticated = False
	db.session.add(user)
	db.session.commit()
	logout_user()
	session.clear()
	return redirect(url_for('index'))

@app.route('/api/notifications/delete/<notification_id>', methods=['GET'])
@login_required
def delete_notification(notification_id):
	notification = Notification.query.get(notification_id)
	user = User.query.filter_by(user_name=session['user']).first()
	if user == notification.parishioner:
		try:
			db.session.delete(notification)
			db.session.commit()
			flash("Successfully deleted this notification!")
		except Exception as e:
			flash("Error deleting this notification. Administration has been notified of this error.")
			report = Report.query.filter_by(body="Error deleting notification due to <{}>".format(e)).first()
			if not report:
				report = Report(body="Error deleting notification due to <{}>".format(e), reported_times=1, reporter_ids=str(user.id))
			else:
				report.reported_times = report.reported_times + 1
				reporter_list = (report.reporter_ids).split(', ')
				if str(user.id) not in reporter_list:
					report.reporter_ids = reporter_ids + ", {}".format(str(user.id))
			try:
				db.session.add(report)
				db.session.commit()
			except:
				pass
	else:
		flash('Unable to proceed with that action. Please try again later.')
	return redirect(url_for('notifications'))

@app.route('/api/tickets/solve/<ticket_id>', methods=['GET'])
@login_required
def solve_ticket(ticket_id):
	ticket = Ticket.query.get(ticket_id)
	user = User.query.filter_by(user_name=session['user']).first()
	actor = user.user_name if user.administrator == False else 'admin'
	if ticket.solved == False:
		correspondence = ticket.correspondence
		merge_message = {'user': 'System Message', 'message': '*Ticket marked as solved by {}.'.format(actor)}
		correspondence.append(merge_message)
		ticket.correspondence = correspondence
		ticket.solved = True
	elif ticket.solved == True:
		correspondence = ticket.correspondence
		merge_message = {'user': 'System Message', 'message': '*Ticket marked as open by {}.'.format(actor)}
		correspondence.append(merge_message)
		ticket.correspondence = correspondence
		ticket.solved = False
	try:
		db.session.add(ticket)
		db.session.commit()
	except:
		status = "closed" if ticket.solved == True else "open"
		flash("Error setting this ticket to {}".format(status))
	return redirect(url_for('ticket_view', ticket_id=ticket_id))

@app.route('/api/tickets/merge/<ticket_id>', methods=['GET', 'POST'])
@login_required
def merge_tickets_lobby(ticket_id):
	form = TicketForm()
	if form.validate_on_submit():
		if form.merge.data:
			return redirect(url_for('merge_tickets', ticket_id=ticket_id, ticket_id_to_merge_into=form.merge.data))
	return render_template('ticket_merge.html', form=form)

@app.route('/api/tickets/merge/<ticket_id>/<ticket_id_to_merge_into>', methods=['GET'])
@login_required
def merge_tickets(ticket_id, ticket_id_to_merge_into):
	user = User.query.filter_by(user_name=session['user']).first
	if user.administrator == False:
		redirect(url_for('index'))
	ticket = Ticket.query.get(ticket_id)
	tmti = Ticket.query.get(ticket_id_to_merge_into)
	if ticket == None:
		flash("Could not find ticket.")
		return render_template(url_for('admin_tickets'))
	elif tmti == None:
		flash("Could not find ticket to merge into.")
		return render_template(url_for('admin_tickets'))
	else:
		pass
	tmti_corr = tmti.correspondence
	merge_message = {'user':'System Message', 'message':"*Ticket #{} merged into Ticket #{}".format(ticket.id, tmti.id)}
	tmti_corr.append(merge_message)
	for corr in ticket.correspondence:
		flash(corr)
		tmti_corr.append(corr)
	tmti.correspondence = tmti_corr
	ticket.solved = True
	try:
		db.session.add(tmti)
		db.session.commit()
	except:
		flash("Error merging tickets.")
		return redirect(url_for('merge_tickets', ticket_id=ticket_id))
	return redirect(url_for('ticket_view', ticket_id=ticket_id_to_merge_into))

@app.route('/profile/', methods=['GET'])
@login_required
def profile():
	return redirect('/profile/me')

@app.route('/profile/me', methods=['GET', 'POST'])
@login_required
#session['user'] required
def profile_me():
	user = User.query.filter_by(user_name=session['user']).first()
	form = RequestForm()
	counter = 0
	for request in user.requests:
		counter += 1
	requests = user.requests.order_by('id desc').limit(10) if counter > 0 else []
	if form.validate_on_submit():
		for word in SWEAR_LIST:
			if word in form.request.data:
				flash("Cannot make this request containing vulgarities.")
				return redirect(url_for('profile'))
		if form.tweet.data:
			try:
				import twitter
				api = twitter.Api(consumer_key=user.twitter_consumer_key,
													consumer_secret=user.twitter_consumer_secret,
													access_token_key=user.twitter_access_token,
													access_token_secret=user.twitter_access_token_secret)
				status = api.PostUpdate(form.request.data)
				r = Request(body=form.request.data, parishioner=user, timestamp=datetime.datetime.utcnow(), anonymous=form.anonymous.data, tweet_id=status.id)
			except:
				flash("Encountered an issue with tweeting this status.")
				r = Request(body=form.request.data, parishioner=user, timestamp=datetime.datetime.utcnow(), anonymous=form.anonymous.data, tweet_id=None)
		else:
			r = Request(body=form.request.data, parishioner=user, timestamp=datetime.datetime.utcnow(), anonymous=form.anonymous.data)
		db.session.add(r)
		db.session.commit()
		flash("Prayer request submitted successfully! You can see it in your profile or temporarily on the front page.")
		return redirect(url_for('profile_me'))
	return render_template('profile.html',
							requests=requests,
							form=form,
							user=user)

@app.route('/profile/contact', methods=['GET', 'POST'])
@login_required
def contact_info():
	user = User.query.filter_by(user_name=session['user']).first()
	if (user.phone_number == None) or (user.home_address == None):
		flash(Markup("<p style='color: red;'><b>Note:</b> Filling out the information on this page is completely optional. If private, this information will only be visible to people who are on your friends list.</p>"))
	form = ContactForm(visible=user.private_contact)
	changed = []
	if form.phone_number.data:
		user.phone_number = form.phone_number.data
		changed.append('Phone Number')
	if form.home_address.data:
		user.home_address = form.home_address.data
		changed.append('Home Address')
	if form.visible.data == user.private_contact:
		pass
	else:
		user.private_contact = form.visible.data
		if user.private_contact == True:
			changed.append('Contact Info Now Private')
		elif user.private_contact == False:
			changed.append('Contact Info Now Public')
	if len(changed) > 0:
		db.session.add(user)
		db.session.commit()
		flash('Successfully changed: {}'.format(changed))
	return render_template('settings_contact.html', form=form, user=user)

@app.route('/profile/twitter', methods=['GET', 'POST'])
@login_required
def twitter_info():
	user = User.query.filter_by(user_name=session['user']).first()
	form = TwitterSettings()
	if form.validate_on_submit():
		if form.consumer_key.data:
			user.twitter_consumer_key = form.consumer_key.data
		if form.consumer_secret.data:
			user.twitter_consumer_secret = form.consumer_secret.data
		if form.access_token.data:
			user.twitter_access_token = form.access_token.data
		if form.access_token_secret.data:
			user.twitter_access_token_secret = form.access_token_secret.data
		user.twitter_enabled = True
		db.session.add(user)
		db.session.commit()
		flash('Successfully updated your Twitter settings!')
	if user.twitter_consumer_key and user.twitter_consumer_secret and user.twitter_access_token and user.twitter_access_token_secret is not None:
		twtr_2_enable = True
	else:
		twtr_2_enable = False
	return render_template('settings_twitter.html', form=form, user=user, tw2=twtr_2_enable)

@app.route('/profile/twitter/disable', methods=['GET'])
@login_required
def twitter_clear():
	user = User.query.filter_by(user_name=session['user']).first()
	user.twitter_enabled = False
	db.session.add(user)
	db.session.commit()
	flash('Successfully disabled Twitter!')
	return redirect(url_for('twitter_info'))

@app.route('/profile/twitter/enable', methods=['GET'])
@login_required
def twitter_enable():
	user = User.query.filter_by(user_name=session['user']).first()
	user.twitter_enabled = True
	db.session.add(user)
	db.session.commit()
	flash('Successfully enabled Twitter!')
	return redirect(url_for('twitter_info'))

@app.route('/profile/me/friends', methods=['GET', 'POST'])
@login_required
def friends():
	user = User.query.filter_by(user_name=session['user']).first()
	friends_list = []
	for friend in user.friends:
		friend_hash = {'name':friend.display_name, 'profile_id':friend.profile_id}
		friends_list.append(friend_hash)
	return render_template('friends.html', friends=friends_list)

@app.route('/profile/<profile_id>', methods=['GET', 'POST'])
@login_required
def get_profile(profile_id):
	if User.query.filter_by(profile_id=profile_id).first() == None:
		return render_template('404.html')
	else:
		user = User.query.filter_by(profile_id=profile_id).first()
		me = User.query.filter_by(user_name=session['user']).first()
		count = 0
		for _ in user.requests.order_by('id desc').all():
			count += 1
		if count < 5:
			requests = user.requests.order_by('id desc').limit(count).all()
		else:
			anon_count = 0
			pub_count = 0
			while pub_count < 5:
				for r in user.requests.order_by('id desc').all():
					if pub_count == 5:
						break
					if r.anonymous == True:
						anon_count += 1
					elif r.anonymous == False:
						pub_count += 1
				if pub_count < 5:
					break
			requests = user.requests.order_by('id desc').limit(pub_count+anon_count).all()
		return render_template('profile_others.html',
								vuser=user, #vuser is the user you're [v]iewing
								muser=me, #me is the current person in the user session
								requests=requests)

@app.route('/profile/<profile_id>/friend', methods=['GET'])
@login_required
def make_friend(profile_id):
	u = User.query.filter_by(user_name=session['user']).first()
	f = User.query.filter_by(profile_id=profile_id).first()
	result = u.friend(f)
	if (result == True) and (u.id is not f.id):
		db.session.add(u)
		db.session.commit()
		if f.display_name is not None:
			flash('Successfully added {} to your friends list!'.format(f.display_name))
		else:
			flash('Successfully added {} to your friends list!'.format(f.profile_id))
	elif result == False:
		flash('{} is already your friend!'.format(f.display_name))
	elif (u.id == f.id):
		flash('You cannot add yourself to your friends list, silly! :)')
	return redirect(url_for('get_profile', profile_id=profile_id))

@app.route('/profile/<profile_id>/unfriend', methods=['GET', 'POST'])
@login_required
def unmake_friend(profile_id):
	u = User.query.filter_by(user_name=session['user']).first()
	f = User.query.filter_by(profile_id=profile_id).first()
	result = u.unfriend(f)
	if result == True:
		db.session.add(u)
		db.session.commit()
		if f.display_name is not None:
			flash('Successfully removed {} from your friends list.'.format(f.display_name))
		else:
			flash('Successfully removed {} from your friends list.'.format(f.user_name))
	elif result == False:
		flash(Markup("<p style='color: red;'>{} is not on your friends list. Cannot remove.</p>".format(f.display_name)))
	return redirect(url_for('get_profile', profile_id=profile_id))

@app.route('/notifications', methods=['GET'])
@login_required
def notifications():
	user = User.query.filter_by(user_name=session['user']).first()
	notifications = user.notifications.all()
	notification_list = []
	for notification in notifications:
		if notification.type == "events":
			notification_list.append(Event.query.filter_by(event_id=notification.type_id).first())
		elif notification.type == "tickets":
			notification_list.append(Ticket.query.get(notification.type_id))
		else: #current 'None' types are: 'deletes'
			notification_list.append('None')
	combos = zip(notifications, notification_list)
	return render_template('notifications.html', notifications=combos)

@app.route('/tickets', methods=['GET', 'POST'])
@login_required
def tickets():
	user = User.query.filter_by(user_name=session['user']).first()
	form = TicketForm()
	if form.validate_on_submit():
		if form.correspondence.data:
			initial_correspondence = [{'user': user.user_name, 'message': form.correspondence.data}]
			ticket = Ticket(correspondence=initial_correspondence,
											parishioner=user,
											solved=False)
			try:
				db.session.add(ticket)
				db.session.commit()
				most_recent_ticket = (Ticket.query.all())[-1::]
				return redirect(url_for('ticket_view', ticket_id=most_recent_ticket[0].id))
			except Exception as e:
				flash("Error creating ticket due to {}".format(e))
		return redirect(url_for('tickets'))
	return render_template("tickets.html", form=form, user=user)

@app.route('/tickets/<ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_view(ticket_id):
	user = User.query.filter_by(user_name=session['user']).first()
	ticket = Ticket.query.get(ticket_id)
	form = TicketForm()
	if ticket == None:
		abort(404)
	correspondence = ticket.correspondence
	if form.validate_on_submit():
		if form.correspondence.data:
			if user.administrator == True:
				correspondence.append({'user': 'admin', 'message': form.correspondence.data})
				notification = Notification.query.filter_by(body="You've received a response to Ticket #{}".format(ticket.id)).first()
				if not notification:
					notification = Notification(parishioner=ticket.parishioner, body="You've received a response to Ticket #{}".format(ticket.id), type="tickets", type_id=ticket.id)
					db.session.add(notification)
			else:
				correspondence.append({'user': user.user_name, 'message': form.correspondence.data})
			ticket.correspondence = correspondence
			try:
				db.session.add(ticket)
				db.session.commit()
			except:
				flash("Error updating this ticket.")
			return redirect(url_for('ticket_view', ticket_id=ticket_id))
	return render_template('ticket_view.html', ticket=ticket, form=form, correspondence=correspondence[::-1], user=user)

@app.route('/tickets/open', methods=['GET', 'POST'])
@login_required
def open_tickets():
	session['ticket_back'] = True
	user = User.query.filter_by(user_name=session['user']).first()
	tickets = user.tickets.all()
	open_tickets = []
	for ticket in tickets:
		if ticket.solved == False:
			open_tickets.append(ticket)
	return render_template('tickets_myopen.html', tickets=open_tickets, user=user)

@app.route('/faq', methods=['GET'])
def faq():
	q = [
		{'question': 'What is AdoreJes.us exactly?',
		'answer':'It\'s simply a social media website -- for church!'},
		{'question': 'What if I have some difficulties understanding how to use AdoreJes.us?',
		'answer': 'AdoreJes.us should be simple and easy to use; however, you will find question marks with a \'tool tip\' next to a few things! If you feel there is something confusing, you may give us feedback on what is confusing and we will be happy to try and make the process simpler.'},
		{'question': 'Why would I want to make an anonymous prayer request?',
		'answer': 'Sometimes, you may have a request that is sensitive and you may not want people to know who exactly it is making the prayer request, but you would still like others to pray for you.'},
		{'question': 'How will God know who I am praying for if I am praying for an anonymous request?',
		'answer': 'There is nothing that God cannot do. When you pray for an anonymous request, God will know exactly who it is that you are praying for.'},
		{'question': 'What kind of prayer requests can I submit?',
		'answer': 'You can submit any types of prayer requests no matter how big, small, private or public. Prayer requests are not, however, status updates or quotes so you will want to refrain from posting song lyrics as a prayer request.'},
		{'question': 'I checked the \'anonymous\' box, but my request doesn\'t look so anonymous. What\'s wrong?',
		'answer': 'Your request is displaying as anonymous to everyone else but you. There is an asterisk (*) next to your name indicating that the request is anonymous. Don\'t worry, your identity is safe :)'},
		{'question':'How can other people find my profile page?',
		'answer': 'You will need to first create your Profile ID, and then people can find it at http://AdoreJes.us/profile/your_id_here'},
		{'question':'I was doing something and I got an error. What happened?',
		'answer':Markup('It\'s more than possible something broke and gave you that error. Most likely we\'ve already been alerted to the issue; however, you\'re more than welcome to send us a message to let us know what happened. If you send us a message, please try to include as much information as possible such as: <br>- What you were doing at the time you got the error <br>- When you had the error <br>- The type of computer you were using at the time <br>- Any other information you may think is relevant')},
		{'question':'What if I don\'t want people to view my profile?',
		'answer':'Simply don\'t enter in a profile ID on your page and people will not be able to find your profile page.'},
		{'question': 'Do I have to use my real information?',
		'answer': 'It\'s not necessary to use your real name or picture, but you\'re more likely to have someone pray for you if that person knows who you are.'},
		{'question':'Why do you require pictures to be uploaded through Gravatar?',
		'answer':'Pictures take up space, but Gravatar offers this neat service that associates a picture with your e-Mail address. You\'d be surprised how many sites will set your profile picture automatically based on your e-Mail through Gravatar!'}
	]
	return render_template('faq.html', q=q)

@app.route('/events', methods=['GET', 'POST'])
@login_required
def events():
	user = User.query.filter_by(user_name=session['user']).first()
	user_events = user.events_attending.all()
	open_events = Event.query.filter_by(complete=False).all()
	all_events = []
	for event in open_events:
		if event.pub_event == True:
			all_events.append(event)
	events = []
	for event in user_events:
		if event in open_events:
			events.append(event)
	return render_template('events.html',
													events=events,
													all_events=all_events)

@app.route('/events/create', methods=['GET', 'POST'])
@login_required
def create_event():
	user = User.query.filter_by(user_name=session['user']).first()
	if user.display_name == None:
		flash(Markup('<p style="color: red;">Please enter a display name before creating an event. People need to know who made the event. :)</p>'))
		return redirect(url_for('prof_settings'))
	form = EventForm()
	if form.validate_on_submit():
		if not form.event_date.data:
			flash(Markup('<p style="color: red;">Please make sure you fill out the {} field!</p>'.format(form.event_id.data)))
		if len(form.event_name.data) > 64:
			flash(Markup('<p style="color: red;">Please enter an event name 64 or less characters</p>'))
			return redirect(url_for('create_event'))
		if ' ' in form.event_id.data:
			flash(Markup('<p style="color: red;">Please make an Event ID without spaces</p>'))
			return redirect(url_for('create_event'))
		for word in SWEAR_LIST:
			if word in form.event_name.data:
				flash("Cannot make this event name containing vulgarities.")
				return redirect(url_for('create_event'))
		for word in SWEAR_LIST:
			if word in form.event_desc.data:
				flash("Cannot make this event description containing vulgarities.")
				return redirect(url_for('create_event'))
		event = Event(
				event_name = form.event_name.data,
				event_desc = form.event_desc.data,
				event_id = form.event_id.data,
				pub_event = form.pub_event.data,
				event_date = datetime.datetime.strptime(form.event_date.data, "%m/%d/%Y").date(),
				coordinator_id = user.id,
				complete = False,
				volunteer_history = [{'user': 'SYSTEM', 'time': datetime.datetime.utcnow(), 'action': 'Created event'}],
				discussion=[{'user': 'SYSTEM', 'message': 'Event discussion opened'}]
			)
		try:
			db.session.add(event)
			db.session.commit()
			flash('Successfully created this event. You may now see this event in your events page.')
			return redirect(url_for('attend_event', event_id=form.event_id.data))
		except Exception as e:
			flash('Unable to create this particular event. Please try again later.')
			return redirect(url_for('create_event'))
	return render_template('event_create.html',
													form=form)

@app.route('/events/manage', methods=['GET'])
@login_required
def manage_events(): #manage all eventSS
	user = User.query.filter_by(user_name=session['user']).first()
	my_events = Event.query.filter_by(coordinator_id=user.id).all()
	return render_template('events_manage_home.html',
													events=my_events)

@app.route('/events/manage/<event_id>', methods=['GET'])
@login_required
def manage_event(event_id): #manage single event
	event = Event.query.filter_by(event_id=event_id).first()
	return render_template('event_manage.html', event=event)

@app.route('/events/manage/<event_id>/settings', methods=['GET', 'POST'])
@login_required
def event_settings(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	form = EventSettings(event_public=event.pub_event, event_complete=event.complete)
	changed = []
	if form.event_name.data:
		event.event_name = form.event_name.data
		changed.append('Event Name')
	if form.event_desc.data:
		event.event_desc = form.event_desc.data
		changed.append('Event Description')
	if form.event_date.data:
		event.event_date = datetime.datetime.strptime(form.event_date.data, "%m/%d/%Y").date()
		changed.append('Event Date')
	if form.event_address.data:
		event.address = form.event_address.data
		changed.append('Event Address')
	if form.event_public.data == event.pub_event:
		pass
	else:
		event.pub_event = form.event_public.data
		if event.pub_event == True:
			changed.append('Now Public')
		elif event.pub_event == False:
			changed.append('Now Private')
	if form.event_complete.data == event.complete:
		pass
	else:
		event.complete = form.event_complete.data
		if event.complete == True:
			changed.append('Marked Finished')
		elif event.complete == False:
			changed.append('Marked Unfinished')
	if form.volunteer_schedule.data:
		try:
			volunteer_schedule = []
			n = 0
			d = [form.volunteer_schedule.data,
					 form.volunteer_schedule_2.data,
					 form.volunteer_schedule_3.data,
					 form.volunteer_schedule_4.data,
					 form.volunteer_schedule_5.data,
					 form.volunteer_schedule_6.data,
					 form.volunteer_schedule_7.data]
			for item in d:
				if item != '':
					n += 1
					day, hours_list = (item.split(': '))#hours_list = 1,2,3,4
					hours = hours_list.split(', ') #hours = [u'1', u'2', u'3', u'4']
					new_hours = []
					ta_l = []
					for h in hours:
						if '*' in h:
							hour, how_many = h.split('*')
							new_hours.append(hour)
							l = []
							for _ in range(int(how_many)):
								l.append(None)
							ta_l.append(l)
						else:
							new_hours.append(h)
							ta_l.append([None])
					times = dict(zip(new_hours, ta_l))
					volunteer_schedule.append(dict({"order": n, "day": day, "times":times}))
			event.volunteer_schedule = json.dumps(volunteer_schedule)
			changed.append('Volunteer Schedule Changed')
		except:
			flash("Error setting this event's hours. Please make sure you've entered the correct format.")
	if len(changed) > 0:
		try:
			db.session.add(event)
			db.session.commit()
			flash('Successfully changed: {}'.format(changed))
			return redirect(url_for('event_settings', event_id=event_id))
		except:
			flash('Error changing the settings for this event.')
			return redirect(url_for('event_settings', event_id=event_id))
	return render_template('settings_event.html', form=form, event=event)

@app.route('/events/manage/<event_id>/delete/confirm', methods=['GET', 'POST'])
@login_required
def confirm_delete_event(event_id): #need to verify coordinator
	event = Event.query.filter_by(event_id=event_id).first()
	return render_template('event_delete_confirmation.html', event=event)

@app.route('/events/manage/<event_id>/delete', methods=['GET'])
@login_required
def delete_event(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	if user.id != event.coordinator_id:
		flash("Not allowed to delete this event!")
		return redirect(url_for('events'))
	try:
		db.session.delete(event)
		db.session.commit()
		flash('Successfully removed this event!')
	except:
		flash('Error removing this event! Please try again later.')
	return redirect(url_for('manage_events'))

@app.route('/events/<event_id>', methods=['GET'])
@login_required
def get_event(event_id):
	user = User.query.filter_by(user_name=session['user']).first()
	users = User.query.all()
	try:
		event = Event.query.filter_by(event_id=event_id).first() #im seeing a complication with this, for similar id'd evts
		coordinator = User.query.filter_by(id=event.coordinator_id).first()
	except:
		flash("Unable to find this event!")
		return redirect(url_for('events'))
	if event.volunteer_schedule is not None:
		volunteer_schedule = json.loads(event.volunteer_schedule)
	else:
		volunteer_schedule = []
	volunteers = []
	for day in volunteer_schedule:
		for time in day['times']:
			n = 0
			for _ in range(len(day['times'][time])):
				vol = User.query.filter_by(display_name=day['times'][time][n]).first()
				n+=1
				if (vol not in volunteers) and (vol is not None):
					volunteers.append(vol)
	attending_users = []
	for u in users: # for a particular [u]ser in all users
		ea = [] # create a list of all events this user is attending
		for evt in u.events_attending: # for each event
			ea.append(evt) # add it to the list
		if event in ea: # if the viewed event is in this list
			if u not in volunteers:
				attending_users.append(u) # add the user to the attending user list
	#---------------------
	return render_template('event_view.html', event=event, coordinator=coordinator,
													user=user, au = attending_users, vs = volunteer_schedule,
													enum = enumerate, sor = sorted, vols = volunteers)

@app.route('/events/<event_id>/invite', methods=['GET', 'POST'])
@login_required
def invite_event(event_id):
	form = BasicForm()
	event = Event.query.filter_by(event_id=event_id).first()
	if form.is_submitted():
		user = User.query.filter_by(profile_id=form.user_name.data).first()
		if user:
			notification = Notification.query.filter_by(body="Event Invite to \"{}\".".format(event.event_name)).first()
			if not notification and (event not in user.events_attending):
				notification = Notification(parishioner=user, body="Event Invite to \"{}\".".format(event.event_name), type="events", type_id=event_id)
				try:
					db.session.add(notification)
					db.session.commit()
					flash('Successfully invited {}'.format(user.profile_id))
				except Exception as e:
					flash('Error inviting {} to this event. Administration has been notified'.format(user.profile_id))
					report = Report.query.filter_by(body="Error inviting user to event due to <{}>".format(e)).first()
					if not report:
						report = Report(body="Error inviting user to event due to <{}>".format(e), reported_times=1, reporter_ids=str(user.id))
					else:
						report.reported_times = report.reported_times + 1
						reporter_list = (report.reporter_ids).split(', ')
						if str(user.id) not in reporter_list:
							report.reporter_ids = report.reporter_ids + ", {}".format(str(user.id))
					db.session.add(report)
					db.session.commit()
			elif event in user.events_attending:
				flash('User is already attending!')
			else:
				flash('User is already invited!')
		else:
			flash('User not found!')
	return render_template("event_invite.html", form=form, evt=event)

@app.route('/events/<event_id>/discussion', methods=['GET', 'POST'])
@login_required
def event_discussion(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	form = EventForm()
	event_discussion = event.discussion
	if form.discussion.data:
		response = {'user': user.profile_id, 'message': form.discussion.data}
		event_discussion.append(response)
		event.discussion = event_discussion
		try:
			db.session.add(event)
			db.session.commit()
		except:
			flash("Error posting your message to this discussion board. Please try again later")
		return redirect(url_for('event_discussion', event_id=event_id))
	if len(event_discussion) > 20:
		event_discussion = event_discussion[-20:][::-1]
	else:
		event_discussion = event_discussion[::-1]
	return render_template('event_discussion.html', event=event, form=form, discussion=event_discussion, user=user)

@app.route('/events/<event_id>/attend', methods=['GET'])
@login_required
def attend_event(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	if user.profile_id == None:
		flash("Please fill in your settings before joining events")
		return redirect(url_for('prof_settings'))
	result = user.attend(event)
	if result == True:
			db.session.add(user)
			db.session.commit()
			flash('Successfully added this event to your attending list!')
	elif result == False:
			flash('You\'re already attending this event!')
	return redirect(url_for('get_event', event_id=event_id))

@app.route('/events/<event_id>/unattend', methods=['GET'])
@login_required
def unattend_event(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	result = user.unattend(event)
	if result == True:
			db.session.add(user)
			db.session.commit()
			flash('Successfully removed this event from your attending list!')
	elif result == False:
			flash('You\'re not attending this event!')
	return redirect(url_for('get_event', event_id=event_id))

@app.route('/events/<event_id>/volunteer', methods=['GET'])
@login_required
def volunteer(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	if event.volunteer_schedule is not None:
		vs = json.loads(event.volunteer_schedule)
	else:
		vs = []
	return render_template('event_volunteer.html', vs = vs,
													event = event, user = user, enum = enumerate, sor = sorted)

@app.route('/events/<event_id>/volunteer/<count>/<time>/<slot>', methods=['GET'])
@login_required
def volunteer_event(event_id, count, time, slot):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	vs = json.loads(event.volunteer_schedule)
	n = 0
	count = int(count)
	changed = [] 
	for item in vs:
		if n == count:
			if user.display_name not in vs[n]['times'][time]:
				vs[n]['times'][time][int(slot)] = user.display_name
				changed.append(1)
				break
			else:
				flash("You cannot sign up for the same time slot twice!")
				break
		else:
			n += 1
	if changed:
		event.volunteer_schedule = json.dumps(vs)
		volunteer_history = event.volunteer_history
		volunteer_history.append({'user': user, 'time': datetime.datetime.utcnow(), 'action': "Signed up"})
		event.volunteer_history = volunteer_history
		try:
			db.session.add(event)
			db.session.commit()
		except:
			flash("Error signing up!")
		flash('Successfully signed up to volunteer for this event!')
	return redirect(url_for('volunteer_event', event_id=event_id))

@app.route('/events/<event_id>/unvolunteer/<count>/<time>/<slot>', methods=['GET'])
@login_required
def unvolunteer_event(event_id, count, time, slot):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	if event.volunteer_schedule is not None:
		vs = json.loads(event.volunteer_schedule)
	else:
		vs = []
	n = 0
	count = int(count)
	for item in vs:
		if n == count:
			vs[n]['times'][time][int(slot)] = None
		else:
			n += 1
	event.volunteer_schedule = json.dumps(vs)
	volunteer_history = event.volunteer_history
	volunteer_history.append({'user': user, 'time': datetime.datetime.utcnow(), 'action': "Cancelled"})
	event.volunteer_history = volunteer_history
	db.session.add(event)
	db.session.commit()
	return redirect(url_for('volunteer_event', event_id=event_id))

@app.route('/events/<event_id>/history', methods=['GET'])
@login_required
def event_history(event_id):
	event = Event.query.filter_by(event_id=event_id).first()
	user = User.query.filter_by(user_name=session['user']).first()
	if user.administrator == False:
		return redirect(url_for('get_event', event_id=event_id))
	if event.volunteer_history:
		history = event.volunteer_history
		history = history[::-1]
	else:
		history = None
	return render_template('event_volunteer_history.html', history=history)
		
#Administration Panel
@app.route('/admin', methods=['GET'])
@login_required
def administration():
	user = User.query.filter_by(user_name=session['user']).first()
	if user.administrator == False:
		flash(Markup('<p style="color: red;"> Please log in to view this page.</p>'))
		return redirect(url_for('login'))
	reports = Report.query.all()
	need_attention = True if reports else False
	return render_template('admin.html', na=need_attention)

@app.route('/admin/reports', methods=['GET'])
@login_required
def admin_reports():
	user = User.query.filter_by(user_name=session['user']).first()
	if user.administrator == False:
		flash(Markup('<p style="color: red;"> Please log in to view this page.</p>'))
		return redirect(url_for('login'))
	reports = Report.query.all()
	request_ids = []
	bodies = []
	rt = [] #reported times
	for report in reports:
		if report.request_id:
			r = Request.query.get(report.request_id)
		else:
			r = None
		request_ids.append(r)
		bodies.append(report.body)
		rt.append(report.reported_times)
	combos = (sorted(zip(reports, request_ids, bodies, rt), key=lambda x:x[3]))[::-1]
	if combos:
		session['report'] = True
	return render_template('admin_reports.html', combos=combos)

@app.route('/admin/tickets', methods=['GET'])
@login_required
def admin_tickets():
	user = User.query.filter_by(user_name=session['user']).first()
	if user.administrator == False:
		flash(Markup('<p style="color: red;"> Please log in to view this page.</p>'))
		return redirect(url_for('login'))
	tickets = Ticket.query.all()
	open_tickets = []
	for ticket in tickets:
		if not ticket.solved:
			open_tickets.append(ticket)
	return render_template('admin_tickets.html', tickets=open_tickets, user=user)

@app.errorhandler(404)
def not_found_error(error):
	pic_list = [
		'nala1', 'nala2'
	]
	pic = pic_list[randint(0,len(pic_list)-1)]
	return render_template('404.html', pic=pic), 404

@app.errorhandler(500)
def internal_error(error):
	flash(error)
	db.session.rollback()
	return render_template('500.html'), 500
