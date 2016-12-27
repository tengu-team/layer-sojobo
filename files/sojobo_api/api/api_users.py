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
        token = juju.authenticate(request.args['api_key'], request.authorization)
        if token.is_admin:
            code, response = 200, juju.get_users_info()
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/', methods=['POST'])
def create_user():
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            if juju.user_exists(data['username']):
                code, response = errors.already_exists('user')
            else:
                juju.create_user(data['username'], data['password'])
                response = {'gui-url': juju.get_gui_url(token)}
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if (juju.user_exists(user) and user == token.username) or token.is_admin:
            code, response = 200, juju.get_user_info(user)
        elif juju.user_exists(user):
            code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/<user>', methods=['DELETE'])
def delete(user):
    try:
        token = juju.authenticate(request.json['api_key'], request.authorization)
        if token.is_admin:
            if juju.user_exists(user):
                if user == 'admin':
                    juju.delete_user(user)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
            else:
                code, response = errors.does_not_exist('errors')
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


# @USERS.route('/<user>', methods=['PUT'])
# def make_admin(user):
#     data = request.json
#     try:
#         token = juju.authenticate(data['api_key'], request.authorization)
#         if juju.user_exists(user):
#             if data['action'] == 'makeadmin':
#                 if token.is_admin and user in juju.get_admins():
#                     code, response = errors.already_exist('admin')
#                 elif token.is_admin:
#                     make_admin(user)
#                     code, response = 200, juju.get_user_info(user)
#                 else:
#                     code, response = errors.no_permission()
#             elif data['action'] == 'changepassword':
#                 if token.is_admin or user == token.username:
#                     juju.change_password(user, data['password'])
#                     code, response = 200, juju.get_user_info(user)
#                 else:
#                     code, response = errors.no_permission()
#             else:
#                 code, response = errors.does_not_exist('action')
#         else:
#             code, response = errors.does_not_exist('user')
#     except KeyError:
#         code, response = errors.invalid_data()
#     return create_response(code, {'message': response})


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def add_to_controller(user, controller):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controller)
        if juju.user_exists(user) and juju.controller_exists(controller):
            if token.c_access == 'superuser' and user != 'admin':
                juju.add_to_controller(token, user, data['access'])
                code, response = 200, juju.get_user_info(user)
            else:
                code, response = errors.no_permission()
        elif juju.controller_exists(controller):
            code, response = errors.does_not_exist('user')
        elif juju.user.exists(user):
            code, response = errors.does_not_exist('controller')
        else:
            code, response = errors.does_not_exist('user and controller')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/<user>/controllers/<controller>', methods=['DELETE'])
def remove_from_controller(user, controller):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controller)
        if juju.user_exists(user) and juju.controller_exists(controller):
            if token.c_access == 'superuser' and user != 'admin':
                code, response = 200, juju.remove_from_controller(token, user)
            else:
                code, response = errors.no_permission()
        elif juju.controller_exists(controller):
            code, response = errors.does_not_exist('user')
        elif juju.user.exists(user):
            code, response = errors.does_not_exist('controller')
        else:
            code, response = errors.does_not_exist('user and controller')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/<user>/controllers/<controller>/<model>', methods=['PUT'])
def add_to_model(user, controller, model):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controller, model)
        if juju.user_exists(user) and juju.controller_exists(controller) and juju.model_exists(model):
            if token.m_access == 'admin' and user != 'admin':
                juju.add_to_model(token, user, data['access'])
                code, response = 200, juju.get_user_info(user)
            else:
                code, response =  errors.no_permission()
        elif juju.user_exists(user) and juju.controller_exists(controller):
            code, response = errors.does_not_exist('model')
        elif juju.controller_exists(controller) and juju.model_exists(model):
            code, response = errors.does_not_exist('user')
        elif juju.user_exists(user) and juju.model_exists(model):
            code, response = errors.does_not_exist('controller')
        elif juju.user_exists(user):
            code, response = errors.does_not_exist('controller and model')
        elif juju.controller_exists(controller):
            code, response = errors.does_not_exist('user and model')
        elif juju.model_exists(model):
            code, response = errors.does_not_exist('user and controller')
        else:
            code, response = errors.does_not_exist('user, controller and model')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['DELETE'])
def remove_from_model(user, controller, model):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controller, model)
        if juju.user_exists(user) and juju.controller_exists(controller) and juju.model_exists(model):
            if token.m_access == 'admin' and user != 'admin':
                juju.remove_from_model(token, user)
                code, response = 200, juju.get_user_info(user)
            else:
                code, response = errors.no_permission()
        elif juju.user_exists(user) and juju.controller_exists(controller):
            code, response = errors.does_not_exist('model')
        elif juju.controller_exists(controller) and juju.model_exists(model):
            code, response = errors.does_not_exist('user')
        elif juju.user_exists(user) and juju.model_exists(model):
            code, response = errors.does_not_exist('controller')
        elif juju.user_exists(user):
            code, response = errors.does_not_exist('controller and model')
        elif juju.controller_exists(controller):
            code, response = errors.does_not_exist('user and model')
        elif juju.model_exists(model):
            code, response = errors.does_not_exist('user and controller')
        else:
            code, response = errors.does_not_exist('user, controller and model')
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})
