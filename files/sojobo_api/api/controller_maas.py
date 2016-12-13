
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
# pylint: disable=c0111,c0301,c0325,r0903,w0406
# !/usr/bin/env python3
# import json
from subprocess import check_call, check_output
from lxml import html
import yaml
import requests


class Token(object):
    def __init__(self, url, auth):
        self.type = 'maas'
        self.url = url
        self.user = auth.username
        self.password = auth.password
        self.api_key = self.get_user_api_key()
        self.login()

    def get_credentials(self):
        return {'auth-type': 'oauth1', 'maas-oath': self.api_key}

    def get_cloud(self):
        return {'type': 'maas', 'auth-types': ['oauth1'], 'endpoint': self.url}

    def login(self):
        return check_output(['maas', 'login', self.user, self.url, self.api_key])

    def get_user_api_key(self):
        # source: https://stackoverflow.com/questions/11892729/how-to-log-in-to-a-website-using-pythons-requests-module/17633072#17633072
        payload = {
            'username': self.user,
            'password': self.password
        }
        with requests.Session() as session:
            session.post('{}/accounts/login/'.format(self.url), data=payload)
            api_page_response = session.get('{}/account/prefs/'.format(self.url))
        tree = html.fromstring(api_page_response.text)
        api_keys = tree.xpath('//div[@id="api"]//input/@value')
        return str(api_keys[-1])


def create_controller(name, region, credentials):
    cloudname = 'maas-{}'.format(name)
    cloud_path = create_cloud_file(cloudname, region)
    cred_path = create_credentials_file(cloudname, credentials)
    check_call(['juju', 'add-cloud', cloudname, cloud_path])
    check_call(['juju', 'add-credential', cloudname, '-f', cred_path])
    return check_output(['juju', 'bootstrap', cloudname, name])


def create_cloud_file(name, endpoint):
    path = '/tmp/cloud.yaml'
    data = {'clouds': {name: {'type': 'maas',
                              'auth-types': ['oauth1'],
                              'endpoint': endpoint}}}
    with open(path, "w") as y_file:
        yaml.dump(data, y_file, default_flow_style=True)
    return path


def create_credentials_file(name, credentials):
    path = '/tmp/credentials.yaml'
    data = {'credentials': {name: {credentials['username']: {'auth-type': 'oauth1', 'maas-oauth': credentials['api_key']}}}}
    with open(path, "w") as y_file:
        yaml.dump(data, y_file, default_flow_style=True)
    return path


def get_supported_series():
    return ['trusty', 'xenial']
#####################################################################################
# Not needed for now
#####################################################################################
# def list_users(maas_token):
#     users = json.loads(check_output(['maas', maas_token.user, 'users', 'read'], universal_newlines=True))
#     return [u['username'] for u in users]


# def create_user(email, password, maas_token):
    # email has to be unique
#     check_call(['maas', maas_token.user,
#                 'users',
#                 'create',
#                 'username={}'.format(email.split('@')[0]),
#                 'email={}'.format(email), 'password={}'.format(password), 'is_superuser=0'])
