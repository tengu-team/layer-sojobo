
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
import json
from subprocess import check_call, check_output
from lxml import html
import requests
from .. .. import helpers


class Token(object):
    def __init__(self, url, auth):
        self.url = url
        self.user = auth.username
        self.password = auth.password
        self.api_key = get_user_api_key(auth.username, auth.password)
        login(self)

    def get_credentials(self):
        return {'auth-type': 'oauth1', 'maas-oath': self.api_key}

    def get_cloud(self):
        return {'type': 'maas', 'auth-types': ['oauth1'], 'endpoint': self.url}


def create_controller(name, endpoint, credentials):
    cloudname = 'maas-{}'.format(name)
    cloud_path = create_cloud_file(cloudname, endpoint)
    cred_path = create_credentials_file(cloudname, credentials)
    check_call(['juju', 'add-cloud', cloudname, cloud_path])
    check_call(['juju', 'add-credential', cloudname, '-f', cred_path])
    output = check_output(['juju', 'bootstrap', cloudname, name])
    return output


def create_cloud_file(name, endpoint):
    path = '{}/cloud.yaml'.format(helpers.api_dir())
    data = {'clouds': {name: {'type': 'maas',
                              'auth-types': '[oauth1]',
                              'endpoint': endpoint}}}
    helpers.write_yaml(path, data)
    return path


def create_credentials_file(name, credentials):
    path = '{}/credentials.yaml'.format(helpers.api_dir())
    data = {name: {credentials['username']: {'auth-type': 'oauth1',
                                             'maas-oauth': get_user_api_key(credentials['username'],
                                                                            credentials['password'])}}}
    helpers.write_yaml(path, data)
    return path


def get_user_api_key(username, password):
    # source: https://stackoverflow.com/questions/11892729/how-to-log-in-to-a-website-using-pythons-requests-module/17633072#17633072
    payload = {
        'username': username,
        'password': password
    }
    with requests.Session() as session:
        login_response = session.post('http://193.190.127.161/MAAS/accounts/login/', data=payload)
        print(login_response)
        api_page_response = session.get('http://193.190.127.161/MAAS/account/prefs/')
        print(api_page_response)
    tree = html.fromstring(api_page_response.text)
    api_keys = tree.xpath('//div[@id="api"]//input/@value')
    return str(api_keys[-1])

def login(token):
    check_call(['maas', 'login', token.user, token.url, token.api_key])
#####################################################################################
# To Check
#####################################################################################
def list_users(maas_token):
    users = json.loads(check_output(['maas', maas_token.user, 'users', 'read'], universal_newlines=True))
    return [u['username'] for u in users]


def create_user(email, password, maas_token):
    # email has to be unique
    check_call(['maas', maas_token.user,
                'users',
                'create',
                'username={}'.format(email.split('@')[0]),
                'email={}'.format(email), 'password={}'.format(password), 'is_superuser=0'])
