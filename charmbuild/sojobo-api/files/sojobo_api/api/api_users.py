# !/usr/bin/env python3
# Copyright (C) 2017  Qrama
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# pylint: disable=c0111,c0301,c0325,c0326,w0406,e0401
###############################################################################
# USER FUNCTIONS
###############################################################################
from flask import request, Blueprint

from sojobo_api.api import w_errors as errors, w_juju as juju


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
    return juju.create_response(code, response)


@USERS.route('/', methods=['POST'])
def create_user():
    data = request.json
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        user = juju.check_input(data['username'])
        if token.is_admin:
            if juju.user_exists(user):
                code, response = errors.already_exists('user')
            else:
                juju.create_user(user, data['password'])
                code, response = 200, juju.get_users_info(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if usr == token.username or token.is_admin:
                code, response = 200, juju.get_user_info(token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['PUT'])
def change_user_password(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if usr == token.username or token.is_admin:
                juju.change_user_password(usr, request.json['password'])
                code, response = 200, juju.get_user_info(token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['DELETE'])
def delete_user(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if token.is_admin:
            if juju.user_exists(usr):
                if usr != 'admin':
                    juju.delete_user(usr)
                    code, response = 200, juju.get_users_info(token)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
            else:
                code, response = errors.does_not_exist('user')
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if token.is_admin or token.username == usr:
                code, response = 200, juju.get_controllers_access(token, usr)
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
        token = juju.authenticate(request.headers['api-key'], request.authorization, juju.check_input(controller))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if token.is_admin or token.username == usr:
                code, response = 200, juju.get_ucontroller_access(token, usr)
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
        token = juju.authenticate(request.headers['api-key'], request.authorization, juju.check_input(controller))
        access = juju.check_access(request.json['access'])
        usr = juju.check_input(user)
        u_exists = juju.user_exists(usr)
        if u_exists:
            if token.c_access == 'superuser' and user != 'admin':
                juju.add_to_controller(token, usr, access)
                code, response = 200, juju.get_controller_access(token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['DELETE'])
def remove_from_controller(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, juju.check_input(controller))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if token.c_access == 'superuser' and user != 'admin':
                juju.remove_from_controller(token, usr)
                code, response = 200, juju.get_controllers_access(token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization, juju.check_input(controller))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if token.is_admin or token.username == usr:
                code, response = 200, juju.get_models_access(token, usr)
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
        token = juju.authenticate(request.headers['api-key'], request.authorization,
                                  juju.check_input(controller), juju.check_input(model))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if token.is_admin or token.username == usr:
                code, response = 200, juju.get_umodel_access(token, usr)
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
        token = juju.authenticate(request.headers['api-key'], request.authorization,
                                  juju.check_input(controller), juju.check_input(model))
        access = juju.check_access(request.json['access'])
        usr = juju.user_exists(user)
        u_exists = juju.user_exists(user)
        if u_exists:
            if (token.m_access == 'admin' or token.c_access == 'superuser') and user != 'admin':
                juju.add_to_model(token, usr, access)
                code, response = 200, juju.get_umodel_access(token, usr)
            else:
                code, response =  errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['DELETE'])
def remove_from_model(user, controller, model):
    try:
        token = juju.authenticate(request.headers['api-key'], request.authorization,
                                  juju.check_input(controller), juju.check_input(model))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if (token.m_access == 'admin' or token.c_access == 'superuser') and user != 'admin':
                juju.remove_from_model(token, usr)
                code, response = 200, juju.get_models_access(token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)
