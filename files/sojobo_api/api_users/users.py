# pylint: disable=c0111,c0301,c0325,c0326,w0406
###############################################################################
# USER FUNCTIONS
###############################################################################
from flask import request, Blueprint

from .. import errors, helpers, juju


USERS = Blueprint('users', __name__)


@USERS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            if juju.user_exists(data['username']):
                code, response = 200, 'The user already exists'
            else:
                juju.create_user(data['username'], data['password'])
                response = {'gui-url': juju.get_gui_url(token)}
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/makeadmin', methods=['POST'])
def make_admin():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            username = data['username']
            if juju.user_exists(username):
                if username in juju.get_admins():
                    code, response = 200, 'The user is already an admin'
                else:
                    code, response = 200, juju.make_admin(username)
            else:
                code, response = errors.no_user()
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/delete', methods=['DELETE'])
def delete():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            username = data['username']
            if juju.user_exists(username):
                admins = juju.get_admins()
                if username not in juju.get_admins() or (username in admins and len(admins)>1):
                    juju.delete_user(username)
                else:
                    code, response = 403, 'This would remove all admins from the system!'
            else:
                code, response = errors.no_user()
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/changepassword', methods=['PUT'])
def change_password():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        username = data['username']
        if juju.user_exists(username):
            if token.is_admin or token.username == username:
                code, response = 200, juju.change_password(username, data['password'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_user()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/addtocontroller', methods=['PUT'])
def add_to_controller():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        username = data['username']
        if juju.user_exists(username):
            if token.c_access == 'superuser' and username not in juju.get_admins():
                code, response = 200, juju.add_to_controller(token, data['username'], data['access'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_user()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/removefromcontroller', methods=['DELETE'])
def remove_from_controller():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        username = data['username']
        if juju.user_exists(username):
            admins = juju.get_admins()
            if (token.c_access == 'superuser' and username not in admins) or (token.is_admin and len(admins)>1):
                code, response = 200, juju.remove_from_controller(token, username)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_user()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/addtomodel', methods=['PUT'])
def add_to_model():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        username = data['username']
        if juju.user_exists(username):
            if token.m_access == 'admin' and username not in juju.get_admins():
                code, response = 200, juju.add_to_model(token, username, data['access'])
            else:
                code, response =  errors.no_permission()
        else:
            code, response = errors.no_user()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@USERS.route('/removefrommodel', methods=['DELETE'])
def remove_from_model():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        username = data['username']
        if juju.user_exists(username):
            if token.m_access == 'admin' and username not in juju.get_admins():
                code, response = 200, juju.remove_from_model(token, username, data['access'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_user()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})
