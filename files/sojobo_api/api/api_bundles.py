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
import requests
import yaml
from flask import request, Blueprint, abort
from sojobo_api.api import w_errors as errors, w_juju as juju, w_datastore as datastore, w_permissions, w_bundles as bundles
from sojobo_api import settings


BUNDLES = Blueprint('bundles', __name__)
REPO = settings.REPO_NAME
LOGGER = logging.getLogger('api_bundles')
LOGGER.setLevel(logging.DEBUG)

@BUNDLES.before_app_first_request
def initialize():
    hdlr = logging.FileHandler('/opt/sojobo_api/log/api_bundles.log')
    hdlr.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOGGER.addHandler(hdlr)

def get():
    return BUNDLES

@BUNDLES.route('/types', methods=['GET'])
def get_all_bundles():
    try:
        LOGGER.info('/BUNDLES/types [GET] => receiving call')
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/BUNDLES/types [GET] => Authenticated!')
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.authorize(auth_data, '/bundles/types', 'get'):
            LOGGER.info('/BUNDLES/types [GET] => Authorized!')
            types = bundles.get_all_bundles(company)
            LOGGER.info('/BUNDLES/types [GET] => Succesfully retrieved all bundles!')
            return juju.create_response(200, types)
        else:
            code, response = errors.no_permission()
            LOGGER.info('/BUNDLES/types [GET] => No Permission to perform this action!')
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@BUNDLES.route('/types', methods=['POST'])
def determine_closest_type():
    try:
        LOGGER.info('/BUNDLES/typess [POST] => receiving call')
        data = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/BUNDLES/types [POST] => Authenticated!')
        if juju.authorize(auth_data, '/bundles/types', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models [POST] => Authorized!', controller)
            if 'applications' in data:
                type = bundles.determine_closest_type(data['applications'])
                if type:
                    LOGGER.info('/BUNDLES/types [POST] => determined type: %s', type['name'])
                    return juju.create_response(200, type)
                else:
                    LOGGER.info('/BUNDLES/types [POST] => no matching type found)
                    return juju.create_response(404, 'Could not find a matching type.')
            else:
                return juju.create_response(400, 'The Body should contain an applications property.')
        else:
            LOGGER.error('/BUNDLES/types [POST] => No Permission to perform this action!')
            code, response = errors.no_permission()
            return juju.create_response(code, response)
    except KeyError:
        error_log()
        return juju.create_response(errors.invalid_data()[0], errors.invalid_data()[1])
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        return juju.create_response(errors.cmd_error(ers)[0], errors.cmd_error(ers)[1])
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)

@BUNDLES.route('/types', methods=['PUT'])
def upload_types():
    #TODO: at the moment only Tengu admin can perform this task. Will be changed
    #      in the future to allow company_admins to upload company specific bundles as well
    try:
        LOGGER.info('/BUNDLES/types [PUT] => receiving call')
        data = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/BUNDLES/types [PUT] => Authenticated!')
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.check_if_admin(request.authorization): #, company):
            if 'repositories' in data:
                LOGGER.info('/BUNDLES/types [PUT] => Start uploading repositories')
                types = bundle.upload_types(data['repositories'], company)
                LOGGER.info('/BUNDLES/types [PUT] => Succesfully uploaded %s repositories', len(types))
                return juju.create_response(200, types)
            else:
                return juju.create_response(400, 'The Body should contain a repositories property.')
        else:
            code, response = errors.no_permission()
            LOGGER.info('/BUNDLES/types [PUT] => No Permission to perform this action!')
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
