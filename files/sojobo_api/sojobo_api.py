
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
import glob
from importlib import import_module
import os
import socket

import helpers

from flask import Flask, redirect
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
    api_list = []
    for path in glob.glob('{}/api_*'.format(helpers.api_dir())):
        api_list.append(path.split('/')[-1])
    return helpers.create_response(200, {'name': socket.gethostname(),
                                         'version': "1.0.0",
                                         'api_dir': helpers.api_dir(),
                                         'used_apis': api_list})


@APP.route('/favicon.ico')
def api_icon():
    return redirect("http://tengu.io/assets/icons/favicon.ico", code=302)
###############################################################################
# START FLASK SERVER
###############################################################################
if __name__ == '__main__':
    # Automatic loading of all the apis if present
    # Not tested and naming must be agreed upon
    for api in glob.glob('{}/api_*'.format(helpers.api_dir())):
        name = api.split('_')[-1]
        blueprint = import_module('{}.{}.{}'.format(api.split('/')[-1], name, name))
        APP.register_blueprint(blueprint, url_prefix='/{}'.format(name))
    APP.run(host='0.0.0.0', port=os.environ.get('SOJOBO_API_PORT'), debug=DEBUG, threaded=True)
