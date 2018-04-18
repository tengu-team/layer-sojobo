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
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302, R0914
import logging
import sys
import ast
import requests
import subprocess as sp
import pyArango.connection as pyArango
sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api import w_juju as juju, w_datastore as datastore


def get_arangodb_connection(host, port, username, password):
    """Creates entry point (connection) to work with ArangoDB."""
    url = 'http://' + host + ':' + port
    connection = pyArango.Connection(arangoURL=url,
                                     username=username,
                                     password=password)
    return connection


def create_arangodb_database(connection):
    if connection.hasDatabase("sojobo"):
        return connection["sojobo"]
    return connection.createDatabase(name="sojobo")


def create_arangodb_collection(sojobo_db, collection_name, edges=False):
    if not has_collection(sojobo_db, collection_name):
        if edges:
            sojobo_db.createCollection(className="Edges", name=collection_name)
        else:
            sojobo_db.createCollection(name=collection_name)


def create_arangodb_collections(sojobo_db):
    create_arangodb_collection(sojobo_db, "users")
    create_arangodb_collection(sojobo_db, "credentials")
    create_arangodb_collection(sojobo_db, "controllers")
    create_arangodb_collection(sojobo_db, "models")
    create_arangodb_collection(sojobo_db, "companies")
    create_arangodb_collection(sojobo_db, "workspace_types")
    create_arangodb_collection(sojobo_db, "companyAccess", edges=True)
    create_arangodb_collection(sojobo_db, "controllerAccess", edges=True)
    create_arangodb_collection(sojobo_db, "modelAccess", edges=True)
    create_arangodb_collection(sojobo_db, "modelType", edges=True)
    create_arangodb_collection(sojobo_db, "bundleTypes")


def has_collection(sojobo_db, collection_name):
    return collection_name in sojobo_db.collections


def setup(cred, c_type, region, host, port, arango_username, arango_password):
    con = get_arangodb_connection(host, port, arango_username, arango_password)
    username = settings.JUJU_ADMIN_USER
    db = create_arangodb_database(con)
    create_arangodb_collections(db)
    datastore.create_workspace_type("A", 0.0010995)
    datastore.create_workspace_type("B", 0.0022569)
    datastore.create_workspace_type("C", 0.0068866)
    credential = {'name': 'default',
                  'type': c_type,
                  'credential': ast.literal_eval(cred)}
    if not datastore.user_exists(username):
        datastore.create_user(username, username)
    datastore.add_credential(username, credential)
    datastore.set_credential_ready(username, 'default')
    mydata = {
              "controller": "login",
              "type": c_type,
              "region": region,
              "credential": credential['name']
            }
    r = requests.post('http://127.0.0.1/tengu/controllers',
                      auth=(username, settings.JUJU_ADMIN_PASSWORD),
                      json=mydata, headers={'api-key': settings.API_KEY})
    print(r.status_code, r.text)
    if not r.status_code == 202:
        sys.exit('Wrong Request sent sojobo!')


if __name__ == '__main__':
    logger = logging.getLogger('setup')
    hdlr = logging.FileHandler('{}/log/setup.log'.format(
                               settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    setup(sys.argv[1], sys.argv[2], sys.argv[3],
          sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
