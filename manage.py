from __init__ import app, db
from models import User, Bookmark
from flask_script import Manager, prompt_bool
from flask_migrate import Migrate, MigrateCommand

manager = Manager(app)
migrate = Migrate(app, db)

manager.add_command('db', MigrateCommand)

@manager.command
def initdb():
	db.create_all()
	db.session.add(User(username='shihao', email='shihao@test.com', password='shihao', authority=2))
	db.session.add(User(username='test', email='test@test.com', password='test', authority=2))
	db.session.commit()
	print 'Iinitialized the database'


@manager.command
def dropdb():
	if prompt_bool(
		"Are you sure you want to lose all your data"):
		db.drop_all()
		print 'Dropped the database'


if __name__ == '__main__':
	manager.run()