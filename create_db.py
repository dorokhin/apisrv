import crypt
from apisrv import db
from apisrv import User, PasswordPolicy
from apisrv import get_hash
db.create_all()

root = User(login='root', password=get_hash('root'), isSupervisor=True)
default_password_policy = PasswordPolicy(length=8,
                                         numbers=False,
                                         uppercase_letters=False,
                                         lowercase_letters=False,
                                         special_symbols=False)
db.session.add(default_password_policy)
db.session.add(root)
db.session.commit()
