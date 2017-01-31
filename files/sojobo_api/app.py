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
# pylint: disable=c0111,c0301
from importlib import import_module
import logging
import os
import socket
from flask import Flask, redirect
from api.w_juju import get_api_dir, create_response
########################################################################################################################
# INIT FLASK
########################################################################################################################
APP = Flask(__name__)
APP.url_map.strict_slashes = False
APP.debug = True
########################################################################################################################
# SETUP LOGGING
########################################################################################################################
logging.basicConfig(filename='/home/ubuntu/flask-sojobo-api.log', level=logging.DEBUG)
########################################################################################################################
# ROUTES
########################################################################################################################
@APP.route('/')
def index():
    return create_response(200, {'name': socket.gethostname(),
                                 'version': "1.0.0",  # see http://semver.org/
                                 'api_dir': get_api_dir(),
                                 'used_apis': get_apis(),
                                 'controllers': get_controllers()})


@APP.route('/favicon.ico')
def api_icon():
    return redirect("http://tengu.io/assets/icons/favicon.ico", code=302)
########################################################################################################################
# REGISTER BLUEPRINTS
########################################################################################################################
def get_apis():
    api_list = []
    for f_path in os.listdir('{}/api'.format(get_api_dir())):
        if 'api_' in f_path and '.pyc' not in f_path:
            api_list.append(f_path.split('.')[0])
    return api_list


def get_controllers():
    c_list = []
    for f_path in os.listdir('{}/controllers'.format(get_api_dir())):
        if 'controller_' in f_path and '.pyc' not in f_path:
            c_list.append(f_path.split('.')[0])
    return c_list


for api in get_apis():
    module = import_module('api.{}'.format(api))
    APP.register_blueprint(getattr(module, 'get')(), url_prefix='/{}'.format(api.split('_')[1]))
for c_type in get_controllers():
    try:
        module = import_module('metering.metering_{}'.format(c_type.split('_')[1]))
        APP.register_blueprint(getattr(module, 'get')(), url_prefix='/metering/{}'.format(c_type.split('_')[1]))
    except ImportError:
        pass
