from app import db, app
import datetime
from hashlib import md5
from sqlalchemy.ext.mutable import MutableDict, Mutable

class MutableDictInList(MutableDict):
    parent = None

    def __init__(self, parent, value):
        self.parent = parent
        super(MutableDictInList, self).__init__(value)

    def changed(self):
        if self.parent:
            self.parent_changed()

class MutableList(Mutable, list):

    def __init__(self, value):
        super(MutableList, self).__init__(self._dict(v) for v in value)

    def _dict(self, value):
        value = MutableDictInList(self, value)
        return value

    def __setitem__(self, key, value):
        list.__setitem__(self, key, self._dict(value))
        self.changed()

    def append(self, value):
        list.append(self, self._dict(value))
        self.changed()

    @classmethod
    def coerce(cls, key, value):
        if not isinstance(value, MutableList):
            if isinstance(value, list):
                return MutableList(value)
            return MutableList.coerce(key, value)
        else:
            return value

    def __getstate__(self):
        return list(dict(v) for v in self)

    def __setstate__(self, state):
        self[:] = [self._dict(value) for value in state]

friended = db.Table('friended',
  db.Column('friender_id', db.Integer, db.ForeignKey('user.id')),
  db.Column('friended_id', db.Integer, db.ForeignKey('user.id')))

events = db.Table('events',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id')))

class User(db.Model):

    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    administrator = db.Column(db.Boolean, index=True, unique=False)
    user_name = db.Column(db.String(24), index=True, unique=True)
    display_name = db.Column(db.String(64), index=True, unique=False)
    profile_id = db.Column(db.String(24), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(128), index=True, unique=False)
    phone_number = db.Column(db.String(10), index=True, unique=False)
    home_address = db.Column(db.String(10), index=True, unique=False)
    private_contact = db.Column(db.Boolean, index=True, unique=False)
    twitter_enabled = db.Column(db.Boolean, index=True, unique=False)
    twitter_consumer_key = db.Column(db.Text, index=True, unique=True)
    twitter_consumer_secret = db.Column(db.Text, index=True, unique=True)
    twitter_access_token = db.Column(db.Text, index=True, unique=True)
    twitter_access_token_secret = db.Column(db.Text, index=True, unique=True)
    requests = db.relationship('Request', backref='parishioner', lazy='dynamic')
    tickets = db.relationship('Ticket', backref='parishioner', lazy='dynamic')
    notifications = db.relationship('Notification', backref='parishioner', lazy='dynamic') #
    events_attending = db.relationship('Event', secondary=events,
                                    backref=db.backref('events', lazy="dynamic"), lazy="dynamic")
    friends = db.relationship('User', secondary=friended,
                              primaryjoin=(friended.c.friender_id == id),
                              secondaryjoin=(friended.c.friended_id == id),
                              backref=db.backref('friended', lazy='dynamic'))
    moderator = db.Column(db.Boolean, index=True, unique=False)
   

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def avatar(self, size, anonymous=False):
        if anonymous == False:
            try:
                return 'https://www.gravatar.com/avatar/%s?d=mm&s=%d' % (md5(self.email.encode('utf-8')).hexdigest(), size)
            except:
                return 'https://www.gravatar.com/avatar/example@throwaway.net?d=mm&s=%d' % (size)   
        else:
            return 'https://www.gravatar.com/avatar/example@throwaway.net?d=mm&s=%d' % (size)

    def attend(self, event):
        if event not in self.events_attending:
            try:
                self.events_attending.append(event)
                return True
            except:
                return False
        else:
            return False

    def unattend(self, event):
        if event in self.events_attending:
            try:
                self.events_attending.remove(event)
                return True
            except:
                return False
        else:
            return False

    def is_friend(self, user): #user is friend, user is not self
      for f in self.friends:
        if user.id == f.id:
          return True
      return False
      #return self.friends.filter(friended.c.friended_id == user.id).count() > 0

    def friend(self, user):
      if not self.is_friend(user):
        self.friends.append(user)
        return True
      else:
        return False

    def unfriend(self, user):
      if self.is_friend(user):
        self.friends.remove(user)
        return True
      else:
        return False

    def volunteer(self, event):
        if event not in self.events_volunteering:
            try:
                self.events_volunteering.append(event)
                return True
            except:
                return False
        else:
            return False

    def unvolunteer(self, event):
        if event in self.events_volunteering:
            try:
                self.events_volunteering.remove(event)
                return True
            except:
                return False
        else:
            return False


    def get_id(self):
        try:
            return unicode(self.id) #python2.7
        except NameError:
            return str(self.id) #python3

    def __repr__(self):
        return '<User %r>' % (self.user_name)


class Request(db.Model):

    __tablename__ = 'request'

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140)) #should be tweetable
    timestamp = db.Column(db.DateTime)
    anonymous = db.Column(db.Boolean)
    tweet_id = db.Column(db.Integer)
    parishioner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Request %r>' % (self.body)

class Report(db.Model):

    __tablename__ = 'report'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    request_id = db.Column(db.Integer)
    reporter_ids = db.Column(db.Text)
    reported_times = db.Column(db.Integer)
    body = db.Column(db.Text)

    def __repr__(self):
        return '<Report for request #%r>' % (self.request_id)

class Notification(db.Model):

    __tablename__ = 'notification'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    body = db.Column(db.String)
    type = db.Column(db.String)
    type_id = db.Column(db.Integer)
    parishioner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<User #%r\'s Notification: %r>' % (self.parishioner_id, self.body)

class Ticket(db.Model):

    __tablename__ = 'ticket'

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.PickleType)
    correspondence = db.Column(MutableList.as_mutable(db.PickleType))
    parishioner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    solved = db.Column(db.Boolean)
    rating = db.Column(db.String) # (dis)satisfied, neutral, etc

    def __repr__(self):
        return 'Ticket #%r' % (self.id)

class Event(db.Model): #ie Event: Adoration Chapel Maintenance

    __tablename__ = 'event'

    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(128))
    event_desc = db.Column(db.Text)
    address = db.Column(db.String(256))
    event_id = db.Column(db.String(20))
    pub_event = db.Column(db.Boolean)
    event_date = db.Column(db.DateTime)
    coordinator_id = db.Column(db.Integer)
    complete = db.Column(db.Boolean)
    volunteer_schedule = db.Column(db.Text)
    volunteer_history = db.Column(MutableList.as_mutable(db.PickleType))
    discussion = db.Column(MutableList.as_mutable(db.PickleType))

    def __repr__(self):
        return '<Event %r>' % (self.event_name)


class Post(db.Model):

    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    #parishioner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
