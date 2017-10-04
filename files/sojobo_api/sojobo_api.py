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
# pylint: disable=c0111,c0301,c0325,c0103
import os
import logging
import logging.handlers
from sojobo_api import settings
from sojobo_api.app import APP, create_response, redirect
########################################################################################################################
# HEADERS SETUP
########################################################################################################################
@APP.after_request
def apply_caching(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization,Content-Type,Location,api-key'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Type,Location'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Accept'] = 'application/json'
    return response
########################################################################################################################
# ERROR HANDLERS
########################################################################################################################
@APP.errorhandler(400)
def bad_request(error):
    return create_response(400, error.description)


@APP.errorhandler(401)
def unauthorized(error):
    return create_response(401, error.description)


@APP.errorhandler(403)
def forbidden(error):
    return create_response(403, error.description)


@APP.errorhandler(404)
def not_found(error):
    return create_response(404, error.description)


@APP.errorhandler(405)
def method_not_allowed(error):
    return create_response(405, error.description)


@APP.errorhandler(409)
def conflict(error):
    return create_response(409, error.description)
########################################################################################################################
# START FLASK SERVER
########################################################################################################################
if __name__ == '__main__':
    hdlr = logging.FileHandler("/opt/sojobo_api/log/flask-sojobo-api.log")
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    APP.logger.addHandler(hdlr)
    APP.logger.setLevel(logging.DEBUG)
    APP.run(host='0.0.0.0', port=int(settings.SOJOBO_API_PORT), threaded=True)
