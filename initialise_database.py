from Interview.routes import bcrypt
from Interview.models import User,db

db.create_all()
user1 = User(username='Admin', password=bcrypt.generate_password_hash(
    'xxxx'), role='admin')
db.session.add(user1)
db.session.commit()

