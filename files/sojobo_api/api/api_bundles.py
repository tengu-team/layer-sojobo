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
from sojobo_api.api.w_juju import create_response
from sojobo_api import settings


BUNDLES = Blueprint('bundles', __name__)

REPO = settings.REPO_NAME
def get():
    return BUNDLES


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


@BUNDLES.route('', methods=['GET'])
@authenticate
def get_bundles():
    i = 1
    res = requests.get('https://api.github.com/orgs/{}/repos'.format(REPO))
    data = []
    while res.json() != [] and res.status_code == 200:
        for b in res.json():
            if 'bundle' in b['name']:
                data.append({
                    'name': b['name'],
                    'description': b['description'],
                    'json': get_json(b['name']),
                    'logo': None
                })
        i += 1
        res = requests.get('https://api.github.com/orgs/{}/repos?page={}'.format(REPO, i))
    return create_response(200, data)


@BUNDLES.route('/<bundle>', methods=['GET'])
@authenticate
def get_bundle(bundle):
    res = requests.get('https://api.github.com/repos/{}/{}'.format(REPO, bundle))
    if res.status_code == 200:
        data = {
            'name': res.json()['name'],
            'description': res.json()['description'],
            'json': get_json(res.json()['name']),
            'logo': None
        }
        return create_response(200, data)
    else:
        abort(404, 'The bundle {}:{} could not be found'.format(REPO, bundle))


def get_json(bundle):
    res = requests.get('https://raw.githubusercontent.com/{}/{}/master/bundle.yaml'.format(REPO, bundle))
    if res.status_code == 200:
        res_dict = yaml.load(res.text)
        return res_dict
    else:
        abort(404, 'The bundle {}:{} could not be found'.format(REPO, bundle))
