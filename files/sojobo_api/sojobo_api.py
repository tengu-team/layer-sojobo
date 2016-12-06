
# Copyright (C) 2016  Ghent University
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
# pylint: disable=c0111,c0301,c0325
# !/usr/bin/env python3
from distutils.util import strtobool
import os
import socket

from control_api import controller, model, user
import helpers

from flask import Flask, request, redirect
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


DEBUG = False
parse_flags_from_environment(['DEBUG', 'FEATURE_FLAG_AUTH'])
###############################################################################
# INIT FLASK
###############################################################################
APP = Flask(__name__)
APP.url_map.strict_slashes = False


@APP.after_request
def apply_caching(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Authentication,Content-Type,Location,id-token'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Type,Location'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE'
    response.headers['Accept'] = 'application/json'
    return response


@APP.errorhandler(403)
def forbidden(error):
    return helpers.create_response(403, {'message': error.description})
###############################################################################
# ROUTES
###############################################################################
@APP.route('/')
def api_root():
    # see http://semver.org/
    return helpers.create_response(200, {"name": socket.gethostname(), "version": "1.0.0"})


@APP.route('/favicon.ico')
def api_icon():
    return redirect("http://tengu.io/assets/icons/favicon.ico", code=302)
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
@APP.route('/controllers/create', methods=['POST'])
def create_controller():
    return controller.create(request)


@APP.route('controllers/delete', methods=['DELETE'])
def delete_controller():
    return controller.delete(request)
###############################################################################
# MODEL FUNCTIONS
###############################################################################
@APP.route('/models/create', methods=['POST'])
def create_model():
    return model.create(request)


@APP.route('/models/delete', method=['DELETE'])
def delete_model():
    return model.delete(request)


@APP.route('/models/<modelname>/status', methods=['GET'])
def status(modelname):
    return model.status(request, modelname)


@APP.route('/models/<modelname>/applications/<appname>/config', methods=['GET'])
def get_config(modelname, appname):
    return model.get_config(request, modelname, appname)
###############################################################################
# USER FUNCTIONS
###############################################################################
@APP.route('/users/create/', methods=['POST'])
def create_user():
    return user.create(request)


@APP.route('/users/delete/', methods=['DELETE'])
def delete_user():
    return user.delete(request)


@APP.route('/users/changepassword/', methods=['PUT'])
def change_password():
    return user.change_password(request)


@APP.route('/users/addtomodel/', methods=['POST'])
def add_to_model():
    return user.add_to_model(request)


@APP.route('/users/removefrommodel/', methods=['POST'])
def remove_from_model():
    return user.remove_from_model(request)


@APP.route('/users/credentials.zip', methods=['GET'])
def get_credentials():
    return user.get_credentials(request)
###############################################################################
# START FLASK SERVER
###############################################################################
if __name__ == '__main__':
    # Enable monitoring and metering module if it's available to the user
    # Not tested and naming must be agreed upon with Sebastien
    try:
        from monitoring_api import monitoring
        APP.register_blueprint(monitoring, url_prefix='/monitoring')
        from metering_api import metering
        APP.register_blueprint(metering, url_prefix='/metering')
    except ImportError:
        pass
    APP.run(host='0.0.0.0', port=os.environ.get('SOJOBO_API_PORT'), debug=DEBUG, threaded=True)
