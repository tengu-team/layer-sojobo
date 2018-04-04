# Copyright (C) 2017 Qrama
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
# pylint: disable=c0111,c0301,c0325,c0326,w0406,e0401,e0611
from functools import wraps
import sys
import traceback
import logging
from werkzeug.exceptions import HTTPException
from flask import request, Blueprint, abort
from sojobo_api.api.w_juju import create_response
from sojobo_api.api import w_juju as juju, w_datastore as ds, w_errors as errors
from sojobo_api import settings


COMPANIES = Blueprint('companies', __name__)
LOGGER = logging.getLogger('api_company')
WS_LOGGER = logging.getLogger('websockets.protocol')
LOGGER.setLevel(logging.DEBUG)
WS_LOGGER.setLevel(logging.DEBUG)


def get():
    return COMPANIES


@COMPANIES.before_app_first_request
def initialize():
    hdlr = logging.FileHandler('/opt/sojobo_api/log/api_company.log')
    hdlr.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOGGER.addHandler(hdlr)
    WS_LOGGER.addHandler(hdlr)


def authenticate(func):
    @wraps(func)
    def function(*args, **kwargs):
        try:
            if request.headers['api-key'] != settings.API_KEY:
                abort(403, 'You do not have permission to use the API')
            else:
                return func(*args, **kwargs)
        except KeyError:
            abort(400, 'The request does not have all the required data or the data is not in the right format.')
    return function


@COMPANIES.route('/', methods=['GET'])
@authenticate
def get_companies():
    try:
        if juju.check_if_admin(request.authorization):
            data = [com for com in ds.get_companies()]
            return create_response(200, data)
        else:
            code, response = errors.no_permission()
            return create_response(code, response)
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@COMPANIES.route('/', methods=['POST'])
@authenticate
def Create_company():
    try:
        data = request.json
        if juju.check_if_admin(request.authorization):
            code, response = 202, juju.create_company(data.get('admin'), data.get('name'), data.get('uri'))
            return create_response(code, response)
        else:
            code, response = errors.no_permission()
            return create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@COMPANIES.route('/<company>', methods=['GET'])
@authenticate
def get_company(company):
    try:
        auth_data = juju.get_connection_info(request.authorization)
        if juju.check_if_admin(auth_data, company):
            data = ds.get_companies()
            return create_response(200, data)
        else:
            code, response = errors.no_permission()
            return create_response(code, response)
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


def error_log():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    for l in lines:
        LOGGER.error(l)
    return lines
