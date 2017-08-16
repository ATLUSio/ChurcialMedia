
from app import db, models

def request_generator(models):
	requests = models.Request.query.all()
	for request in requests:
		yield request.id, request.body, request.parishioner.user_name

requester = request_generator(models)

while 1:
	nexter = raw_input("Next?")
	try:
		if nexter == "":
			ident, body, username = (next(requester))
			print("ID {} // BODY {} // USER {}".format(ident, body, username))
		elif nexter == "delete":
			r = models.Request.query.filter_by(id=ident).first()
			db.session.delete(r)
			db.session.commit()
			print("Deleted '{}'".format(r))
	except StopIteration:
		stopped = raw_input("End of iteration.")
		break
	except Exception as e:
		print("Something broke: ".format(e))