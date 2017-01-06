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
# pylint: disable=c0111,c0301,c0325,c0103

from distutils.util import strtobool
from importlib import import_module
import json
import logging
import os
import socket

from flask import Flask, redirect, Response

#
# Init feature flags and global variables
#
# Docs:
# - https://flask-featureflags.readthedocs.io/en/latest/
# - http://groovematic.com/2014/10/feature-flags-in-flask/
# - http://zurb.com/forrst/posts/Feature_Flags_in_python-ulC
#
def parse_flags_from_environment(flags):
    """Creates a global bool variable for each name in `flags`.
    The value of the global variable is
     - `True` if an environment variable with the same name exists and is interpreted as True (by strtobool(value.lower())).
     - `False` in any other case
    """
    for flagname in flags:
        value = False
        try:
            value = strtobool(os.environ.get(flagname, 'False').lower())
        except ValueError:
            pass
        globals()[flagname] = value


def get_api_dir():
    return os.environ.get('SOJOBO_API_DIR')
    # return '/home/mathijs/Documents/repos/Sojobo-api/files/sojobo_api'


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


def create_response(http_code, return_object):
    return Response(
        json.dumps(return_object),
        status=http_code,
        mimetype='application/json',
    )


# DEBUG = False
parse_flags_from_environment(['FEATURE_FLAG_AUTH'])
###############################################################################
# SETUP LOGGING
###############################################################################
logging.basicConfig(filename='/home/ubuntu/flask-sojobo-api.log', level=logging.DEBUG)
###############################################################################
# INIT FLASK
###############################################################################
APP = Flask(__name__)
APP.url_map.strict_slashes = False
APP.debug = True


@APP.after_request
def apply_caching(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Authentication,Content-Type,Location,id-token'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Type,Location'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE'
    response.headers['Accept'] = 'application/json'
    return response


@APP.errorhandler(400)
def bad_request(error):
    return create_response(400, {'message': error.description})


@APP.errorhandler(401)
def unauthorized(error):
    return create_response(401, {'message': error.description})


@APP.errorhandler(403)
def forbidden(error):
    return create_response(403, {'message': error.description})


@APP.errorhandler(404)
def not_found(error):
    return create_response(404, {'message': error.description})


@APP.errorhandler(405)
def method_not_allowed(error):
    return create_response(405, {'message': error.description})


@APP.errorhandler(409)
def conflict(error):
    return create_response(409, {'message': error.description})
###############################################################################
# ROUTES
###############################################################################
@APP.route('/')
def api_root():
    return create_response(200, {'message': {'name': socket.gethostname(),
                                             'version': "1.0.0",  # see http://semver.org/
                                             'api_dir': get_api_dir(),
                                             'used_apis': get_apis(),
                                             'controllers': get_controllers()}})


@APP.route('/favicon.ico')
def api_icon():
    return redirect("http://tengu.io/assets/icons/favicon.ico", code=302)
###############################################################################
# START FLASK SERVER
###############################################################################
if __name__ == '__main__':
    for api in get_apis():
        module = import_module('api.{}'.format(api))
        APP.register_blueprint(getattr(module, 'get')(), url_prefix='/{}'.format(api.split('_')[1]))
    APP.run(host='0.0.0.0', port=int(os.environ.get('SOJOBO_API_PORT')), threaded=True)
