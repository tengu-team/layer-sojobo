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
# pylint: disable=c0111,c0301
from importlib import import_module
import logging
import os
from flask import Flask, redirect, request, abort
from sojobo_api import settings
from sojobo_api.api.w_juju import create_response
from sojobo_api.api.w_errors import invalid_data, unauthorized
########################################################################################################################
# INIT FLASK
########################################################################################################################
APP = Flask(__name__)
APP.url_map.strict_slashes = False
APP.debug = True
APP.config.from_object('sojobo_api.settings')
########################################################################################################################
# SETUP LOGGING
########################################################################################################################
logging.basicConfig(filename='/home/ubuntu/flask-sojobo-api.log', level=logging.DEBUG)
########################################################################################################################
# ROUTES
########################################################################################################################
@APP.route('/')
def index():
    try:
        if request.headers['api-key'] == settings.API_KEY:
            code, response = 200, {'version': "1.0.0",  # see http://semver.org/
                                   'used_apis': get_apis(),
                                   'controllers': get_controllers()}
        else:
            error = unauthorized()
            abort(error[0], error[1])
    except KeyError:
        code, response = invalid_data()
    return create_response(code, response)


@APP.route('/favicon.ico')
def api_icon():
    return redirect("http://tengu.io/assets/icons/favicon.ico", code=302)
########################################################################################################################
# REGISTER BLUEPRINTS
########################################################################################################################
def get_apis():
    api_list = []
    for f_path in os.listdir('{}/api'.format(APP.config['SOJOBO_API_DIR'])):
        if 'api_' in f_path and '.pyc' not in f_path:
            api_list.append(f_path.split('.')[0])
    return api_list


def get_controllers():
    c_list = []
    for f_path in os.listdir('{}/controllers'.format(APP.config['SOJOBO_API_DIR'])):
        if 'controller_' in f_path and '.pyc' not in f_path:
            c_list.append(f_path.split('.')[0])
    return c_list


for api in get_apis():
    module = import_module('sojobo_api.api.{}'.format(api))
    APP.register_blueprint(getattr(module, 'get')(), url_prefix='/{}'.format(api.split('_')[1]))
