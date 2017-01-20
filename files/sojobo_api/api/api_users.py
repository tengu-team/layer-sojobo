# pylint: disable=c0111,c0301,c0325,c0326,w0406,e0401
###############################################################################
# USER FUNCTIONS
###############################################################################
from flask import request, Blueprint

from api import w_errors as errors, w_juju as juju
from sojobo_api import create_response


USERS = Blueprint('users', __name__)


def get():
    return USERS


@USERS.route('/', methods=['GET'])
def get_users_info():
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if token.is_admin:
            code, response = 200, juju.get_users_info(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/', methods=['POST'])
def create_user():
    data = request.json
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if token.is_admin:
            if juju.user_exists(data['username']):
                code, response = errors.already_exists('user')
            else:
                code, response = 200, juju.create_user(token, data['username'], data['password'])
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if juju.user_exists(user):
            if user == token.username or token.is_admin:
                code, response = 200, juju.get_user_info(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>', methods=['PUT'])
def change_user_password(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if juju.user_exists(user):
            if user == token.username or token.is_admin:
                code, response = 200, juju.change_user_password(token, user, request.json['password'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>', methods=['DELETE'])
def delete(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if token.is_admin:
            if juju.user_exists(user):
                if user != 'admin':
                    code, response = 200, juju.delete_user(token, user)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
            else:
                code, response = errors.does_not_exist('user')
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        if juju.user_exists(user):
            if token.is_admin or token.username == user:
                code, response = 200, juju.get_controllers_access(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return code, response


@USERS.route('/<user>/controllers/<controller>', methods=['GET'])
def get_ucontroller_access(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller)
        if juju.user_exists(user):
            if token.is_admin or token.username == user:
                code, response = 200, juju.get_ucontroller_access(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return code, response


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def add_to_controller(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller)
        access = request.json['access']
        u_exists = juju.user_exists(user)
        a_exists = juju.c_access_exists(access)
        if u_exists and a_exists:
            if token.c_access == 'superuser' and user != 'admin':
                code, response = 200, juju.add_to_controller(token, user, access)
            else:
                code, response = errors.no_permission()
        elif a_exists:
            code, response = errors.does_not_exist('user')
        elif u_exists:
            code, response = errors.does_not_exist('controller access')
        else:
            code, response = errors.does_not_exist('user, and controller access')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['DELETE'])
def remove_from_controller(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller)
        if juju.user_exists(user):
            if token.c_access == 'superuser' and user != 'admin':
                code, response = 200, juju.remove_from_controller(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller)
        if juju.user_exists(user):
            if token.is_admin or token.username == user:
                code, response = 200, juju.get_models_access(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors. invalid_data()
    return code, response


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_access(user, controller, model):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller, model)
        if juju.user_exists(user):
            if token.is_admin or token.username == user:
                code, response = 200, juju.get_umodel_access(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return code, response


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['PUT'])
def add_to_model(user, controller, model):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller, model)
        access = request.json['access']
        u_exists = juju.user_exists(user)
        a_exists = juju.m_access_exists(access)
        if u_exists and a_exists:
            if (token.m_access == 'admin' or token.c_access == 'superuser') and user != 'admin':
                juju.add_to_model(token, user, access)
                code, response = 200, access
            else:
                code, response =  errors.no_permission()
        elif u_exists:
            code, response = errors.does_not_exist('model access')
        elif a_exists:
            code, response = errors.does_not_exist('user')
        else:
            code, response = errors.does_not_exist('user and model access')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['DELETE'])
def remove_from_model(user, controller, model):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, controller, model)
        if juju.user_exists(user):
            if (token.m_access == 'admin' or token.c_access == 'superuser') and user != 'admin':
                code, response = 200, juju.remove_from_model(token, user)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, response)
