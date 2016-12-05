
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
class AWS_Token(object):
    def __init__(self, url, access_key, secret_key):
        self.url = url
        self.access_key = access_key
        self.secret_key = secret_key


def get_credentials(juju_token):
    return {'aws': {juju_token.username, {'auth-type': 'access-key',
                               'access-key': juju_token.c_token.access_key,
                               'secret-key': juju_token.c_token.secret_key}
                   }
           }


def get_clouds(cloud, juju_token):
    return {'clouds':{cloud: {'type': 'aws', 'auth-types': ['access-key'], 'endpoint': juju_token.c_token.url}}}
