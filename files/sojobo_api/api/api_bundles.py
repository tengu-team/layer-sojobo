# pylint: disable=c0111,c0301
#!/usr/bin/env python3.6
from functools import wraps
import requests
import json
import yaml
from flask import request, Blueprint, abort
from sojobo_api.api.w_juju import create_response
from sojobo_api import settings


BUNDLES = Blueprint('bundles', __name__)


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
    res = requests.get('https://api.github.com/orgs/tengu-team/repos')
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
        res = requests.get('https://api.github.com/orgs/tengu-team/repos?page={}'.format(i))
    return create_response(200, data)


@BUNDLES.route('/<bundle>', methods=['GET'])
@authenticate
def get_bundle(bundle):
    res = requests.get('https://api.github.com/repos/tengu-team/{}'.format(bundle))
    if res.status_code == 200:
        data = {
            'name': res.json()['name'],
            'description': res.json()['description'],
            'json': get_json(res.json()['name']),
            'logo': None
        }
        return create_response(200, data)
    else:
        abort(404, 'The bundle {} could not be found'.format(bundle))


def get_json(bundle):
    res = requests.get('https://raw.githubusercontent.com/tengu-team/{}/master/bundle.yaml'.format(bundle))
    if res.status_code == 200:
        res_dict = yaml.load(res.text)
        json_file = json.dumps(res_dict)
        return json_file
    else:
        return None
