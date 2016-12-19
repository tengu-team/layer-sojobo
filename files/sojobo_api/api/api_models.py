# !/usr/bin/env python3
# Copyright (C) 2016  Qrama
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
# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# MODEL FUNCTIONS
###############################################################################
from flask import request, Blueprint
from api import w_errors as errors
from sojobo_api import create_response
from api import w_juju as juju


MODELS = Blueprint('jmodels', __name__)


def get():
    return MODELS


@MODELS.route('/')
def home():
    return create_response(200, {'name': 'Models API',
                                         'version': "1.0.0",  # see http://semver.org/
                                        })


@MODELS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        model = data['model']
        if juju.model_exists(token, model):
            code, response = 200, 'The model already exists'
        else:
            if token.c_access == 'add-model' or token.c_access == 'superuser':
                juju.create_model(token, model, data.get('ssh_key', None))
                code, response = 200, {'model-name': token.m_name,
                                       'model-fullname': token.m_shared_name(),
                                       'gui-url': juju.get_gui_url(token)}
            else:
                code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@MODELS.route('/delete', methods=['DELETE'])
def delete():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.delete_model(token)
            code, response = 200, 'The model has been destroyed'
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@MODELS.route('/addsshkey', methods=['PUT'])
def add_ssh_key():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.add_ssh_key(token, data['ssh_key'])
            code, response = 200, 'The ssh-key has been added'
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@MODELS.route('/removesshkey', methods=['PUT'])
def remove_ssh_key():
    data = request.format
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.remove_ssh_key(token, data['ssh_key'])
            code, response = 200, 'The ssh-key has been removed'
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@MODELS.route('/<controllername>/<modelname>/status', methods=['GET'])
def status(controllername, modelname):
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization, controllername, modelname)
        if token.m_access:
            code, response = 200, juju.model_status(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@MODELS.route('/getmodels/<controllername>', methods=['GET'])
def get_models(controllername):
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization, controllername)
        code, response = juju.get_models(token)
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})
