
from app import models, db
from random import randint

user = models.User(user_name='123456789')
db.session.add(user)
db.session.commit()

while 1:
	answer = raw_input("Create request?\n> ")
	if answer == "n":
		break
	else:
		r = models.Request(body="Sample text, lorem impsum, all that jazz.", parishioner=user)
		db.session.add(r)
		db.session.commit()