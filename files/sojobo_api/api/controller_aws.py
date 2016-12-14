
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
# pylint: disable=c0111,c0301,c0325, r0903,w0406
# !/usr/bin/env python3
from subprocess import check_output, check_call
import yaml


class Token(object):
    def __init__(self, url, auth):
        self.access, self.secret = get_credentials(auth)
        self.type = 'aws'
        self.supportlxd = False
        self.url = url


    def get_credentials(self):
        return {'auth-type': 'access-key', 'access-key': self.access, 'secret-key': self.secret}

    def get_cloud(self):
        return {'type': 'aws', 'auth-types': ['access-key'], 'endpoint': self.url}


def get_credentials(auth):
    with open('/home/ubuntu/.local/share/juju/credentials.yaml', 'r') as cred:
        credentials = yaml.load(cred)['credentials']['aws'][auth.username]
    return credentials['access-key'], credentials['secret-key']


def create_controller(name, region, credentials):
    path = create_credentials_file(region, credentials)
    check_call(['juju', 'add-credential', 'aws', '-f', path])
    output = check_output(['juju', 'bootstrap', 'aws/{}'.format(region), name])
    return output


def get_supported_series():
    return ['precise', 'trusty', 'xenial', 'yakkety']


def create_credentials_file(region, credentials):
    path = '/tmp/credentials.yaml'
    data = {'aws': {'default-credential': 'admin',
                    'default-region': region,
                    'admin': {'auth-type': 'access-key',
                              'access-key': credentials['access_key'],
                              'secret-key': credentials['secret_key']}}}
    with open(path, 'w') as dest:
        yaml.dump(data, dest, default_flow_style=True)
    return path
