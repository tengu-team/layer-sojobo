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
from werkzeug.utils import secure_filename
from api import w_errors as errors
from sojobo_api import create_response, get_api_dir
from api import w_juju as juju


CONTROLLERS = Blueprint('controllers', __name__)


def get():
    return CONTROLLERS


@CONTROLLERS.route('/')
def home():
    return create_response(200, {'name': 'Controllers API',
                                 'controllers': list(juju.get_controller_types().keys())
                                        })


@CONTROLLERS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            if 'file' in request.files:
                cfile = request.files['file']
                cfile.save('{}/files'.format(get_api_dir), '{}.json'.format(data['credentials']['project-id']))
                response = juju.create_controller(token, data['type'], data['name'], data['region'],
                                                  data['credentials'], cfile)
            else:
                response = juju.create_controller(token, data['type'], data['name'], data['region'], data['credentials'])
            code = 200
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@CONTROLLERS.route('/delete', methods=['DELETE'])
def delete():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        if token.c_access == 'superuser':
            code, response = 200, juju.delete_controller(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})


@CONTROLLERS.route('/backup', methods=['GET'])
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


@CONTROLLERS.route('/getcontrollers', methods=['GET'])
def get_controllers():
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization)
        code, response = 200, juju.get_controllers(token)
    except KeyError:
        code, response = errors.invalid_data()
    return create_response(code, {'message': response})
