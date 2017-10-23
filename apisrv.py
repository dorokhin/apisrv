import crypt
from hmac import compare_digest as compare_hash
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask import Flask, abort, jsonify, request, make_response
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, get_raw_jwt
)

application = Flask(__name__)
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(application)
ma = Marshmallow(application)
application.config['JWT_SECRET_KEY'] = 'A5mWedudhsgd4DgjnFuekKHhSLjHnGEoXksls'
application.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=2)
application.config['JWT_BLACKLIST_ENABLED'] = True
application.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(application)

blacklist = set()


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'login', 'isExternalAccount', 'isSupervisor', 'created')

users_schema = UserSchema(many=True)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(512), unique=False, nullable=True)
    isExternalAccount = db.Column(db.Boolean, default=False)
    isSupervisor = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return "<User {}>".format(self.username)


class PasswordPolicy(db.Model):
    __tablename__ = "password_policy"

    id = db.Column(db.Integer, primary_key=True)
    length = db.Column(db.Integer, default=12)
    numbers = db.Column(db.Boolean, default=True)
    uppercase_letters = db.Column(db.Boolean, default=True)
    lowercase_letters = db.Column(db.Boolean, default=True)
    special_symbols = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<Password policy>"


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


def check_supervisor_permission(identity):
    _identity = User.query.filter_by(login=identity).first()
    if _identity.isSupervisor:
        return True


def get_hash(password):
    salt = '$6$LMJJONIovTcU.8f.$s7IraH5TPb0tZkda3pskYNCrfhuvY6G8tc39zRCrbQLL/qtJpFwIKwBGN2yEHmwOThPUAn36sOsuSSIC/BOIG1'
    return crypt.crypt(password, salt=salt)


def check_password_policy(password):
    special_chars = '@#&'
    _password_policy = PasswordPolicy.query.filter_by(id=1).first()
    if len(password) >= _password_policy.length:
        if _password_policy.numbers:
            if not any(char.isdigit() for char in password):
                return False
        if _password_policy.uppercase_letters:
            if not any(char.isupper() for char in password):
                return False
        if _password_policy.lowercase_letters:
            if not any(char.islower() for char in password):
                return False
        if _password_policy.special_symbols:
            if not any(char in special_chars for char in password):
                return False
        return True
    else:
        return False


def _user_instance(_login, _password, is_supervisor=False):
    return User(login=_login, password=get_hash(_password), isSupervisor=is_supervisor)


@application.route("/api")
def index():
    return jsonify({"api": {"version": "0.0.1"}})


@application.route("/api/accounts", methods=["GET"])
@jwt_required
def get_accounts_list():
    if not check_supervisor_permission(get_jwt_identity()):
        return jsonify({"msg": "Unauthorized"}), 401
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify({"users": result.data})


@application.route("/api/accounts", methods=["POST"])
@jwt_required
def create_account():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    _params = request.get_json()
    _login = _params.get("login", None)
    _password = _params.get("password", None)
    _isExternalAccount = _params.get("isExternalAccount", None)
    _isSupervisor = _params.get("isSupervisor", None)

    if not check_supervisor_permission(get_jwt_identity()):
        return jsonify({"msg": "Unauthorized"}), 401

    if not check_password_policy(_password):
        return jsonify({"msg": "The new password does not match the password policy"}), 400

    if not _login:
        return jsonify({"msg": "Missing login parameter"}), 400

    _user = User.query.filter_by(login=_login).first()
    if _user:
        return make_response(jsonify({"msg": "user already exist"}), 409)

    if not _isExternalAccount and not _password:
        return jsonify({"msg": "Bad username or password"}), 400

    if _isExternalAccount:
        _record = User(login=_login, password=None, isExternalAccount=True)
        db.session.add(_record)
        db.session.commit()
        return jsonify({"msg": "created"}), 201

    if _isSupervisor:
        is_supervisor = True
    else:
        is_supervisor = False

    _record = _user_instance(_login, get_hash(_password), is_supervisor=is_supervisor)
    db.session.add(_record)
    db.session.commit()
    ret = {"msg": "created"}
    return jsonify(ret), 201


@application.route("/api/accounts/<int:user_id>/password", methods=["PUT"])
@jwt_required
def change_user_password(user_id):
    if not check_supervisor_permission(get_jwt_identity()):
        return jsonify({"msg": "Unauthorized"}), 401
    if user_id <= 0:
        abort(400)

    _params = request.get_json()
    _old_password = _params.get("oldPassword", None)
    _new_password = _params.get("newPassword", None)
    if not check_password_policy(_new_password):
        return jsonify({"msg": "The new password does not match the password policy"}), 400

    _user = User.query.filter_by(id=user_id).first()
    if _user.password == get_hash(_old_password):
        _user.password = get_hash(_new_password)
        db.session.commit()
    else:
        return jsonify({"msg": "forbidden"}), 401
    return jsonify({"msg": "success"})


@application.route("/api/accounts/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    _params = request.get_json()
    _login = _params.get("login", None)
    _password = _params.get("password", None)

    if not _login:
        return jsonify({"msg": "Missing login parameter"}), 400

    _user = User.query.filter_by(login=_login).first()
    if _user is None:
        return make_response(jsonify({"msg": "forbidden"}), 401)

    if not _user.isExternalAccount and not _password:
        return jsonify({"msg": "Bad username or password"}), 401

    if _user.isExternalAccount:
        return jsonify({"jwt": create_access_token(identity=_login)}), 200

    if not compare_hash(get_hash(_password), _user.password):
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    ret = {"jwt": create_access_token(identity=_login)}
    return jsonify(ret), 200


@application.route('/api/accounts/<int:user_id>', methods=["DELETE"])
@jwt_required
def delete_user(user_id):
    _user = User.query.filter_by(id=user_id).first()
    db.session.delete(_user)
    db.session.commit()

    return jsonify({"msg": "success"}), 200


@application.route('/api/accounts/logout', methods=["POST"])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200


@application.route("/api/accounts/password/policy", methods=["POST"])
@jwt_required
def change_password_policy():
    if not check_supervisor_permission(get_jwt_identity()):
        return jsonify({"msg": "Unauthorized"}), 401
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    _params = request.get_json()
    _length = _params.get("length", 8)
    _numbers = _params.get("numbers", False)
    _uppercase_letters = _params.get("uppercase letters", False)
    _lowercase_letters = _params.get("lowercase letters", False)
    _special_symbols = _params.get("special symbols", False)

    _password_policy = PasswordPolicy.query.filter_by(id=1).first()
    _password_policy.length = _length
    _password_policy.numbers = _numbers
    _password_policy.uppercase_letters = _uppercase_letters
    _password_policy.lowercase_letters = _lowercase_letters
    _password_policy.special_symbols = _special_symbols
    db.session.commit()

    return jsonify({"msg": "policy changed"})


@application.errorhandler(404)
def not_found(error):
    return make_response(jsonify({"msg": "Resource not found"}), 404)


if __name__ == "__main__":
    application.run(host='0.0.0.0')
