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
# CONTROLLER FUNCTIONS
###############################################################################
import shutil

from flask import send_file, request, Blueprint
from api import w_errors as errors, w_juju as juju
from sojobo_api import create_response, get_api_dir


TENGU = Blueprint('tengu', __name__)


def get():
    return TENGU


@TENGU.route('/', methods=['GET'])
def get_all_info():
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization)
        code, response = 200, juju.get_all_info(token)  # ToDo: write this function
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>', methods=['GET'])
def get_controller_info(controllername):
    data = request.args
    try:
        juju.authenticate(data['api_key'], request.authorization)
        code, response = 200, juju.get_controller_info(controllername)
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>', methods=['POST'])
def create_controller(controllername):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            if juju.controller_exists(controllername):
                code, response = errors.already_exists('controller')
            elif 'file' in request.files:
                cfile = request.files['file']
                cfile.save('{}/files'.format(get_api_dir), '{}.json'.format(data['credentials']['project-id']))
                response = juju.create_controller(token, data['type'], controllername, data['region'],
                                                  data['credentials'], cfile)
            else:
                response = juju.create_controller(token, data['type'], controllername, data['region'], data['credentials'])
            code = 200
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>', methods=['DELETE'])
def delete_controller(controllername):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controllername)
        if token.c_access == 'superuser':
            code, response = 200, juju.delete_controller(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/backup', methods=['GET'])
def backup_controllers():
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization)
        if token.is_admin:
            apidir = get_api_dir()
            homedir = '/home/ubuntu/.local/share/juju'
            shutil.copy2('{}/install_credentials.py'.format(apidir), '{}/backup/install_credentials.py'.format(apidir))
            shutil.copy2('{}/clouds.yaml'.format(homedir), '{}/backup/clouds.yaml'.format(apidir))
            shutil.copy2('{}/credentials.yaml'.format(homedir), '{}/backup/credentials.yaml'.format(apidir))
            shutil.copy2('{}/controllers.yaml'.format(homedir), '{}/backup/controllers.yaml'.format(apidir))
            shutil.make_archive('{}/backup'.format(apidir), 'zip', '{}/backup/'.format(apidir))
            return send_file('{}/backup.zip'.format(apidir))
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>/<modelname>', methods=['GET'])
def get_model_info(controllername, modelname):
    data = request.args
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controllername, modelname)
        code, response = 200, juju.get_model_info(token)
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>/<modelname>', methods=['PUT'])
def create_model(controllername, modelname):
    data = request.json
    try:
        token = juju.authenticate(data['api_key'], request.authorization, controllername)
        if juju.model_exists(controllername, modelname):
            code, response = errors.already_exists('model')
        elif token.c_access == 'add-model' or token.c_access == 'superuser':
            juju.create_model(token, modelname, data.get('ssh_key', None))
            code, response = 200, {'model-name': token.m_name,
                                   'model-fullname': token.m_shared_name(),
                                   'gui-url': juju.get_gui_url(token)}
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@TENGU.route('/<controllername>/<modelname>', methods=['DELETE'])
def delete():
    data = request.json
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
