#!/usr/bin/python3
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
# pylint: disable=c0111,c0103,c0301,e0401
from base64 import b64encode
from hashlib import sha256
import os
import shutil
import sys
import subprocess
from charmhelpers.core import unitdata
from charmhelpers.core.templating import render
from charmhelpers.core.hookenv import status_set, log, config, open_port, close_port, unit_private_ip, application_version_set, leader_get, leader_set
from charmhelpers.core.host import service_restart, chownr, adduser
from charms.reactive import hook, when, when_not, set_state, remove_state
import charms.leadership
import pyArango.connection as pyArango



API_DIR = '/opt/sojobo_api'
USER = 'sojobo'
GROUP = 'www-data'
HOST = unit_private_ip()
db = unitdata.kv()
###############################################################################
# INSTALLATION AND UPGRADES
###############################################################################
@when('juju.installed')
@when_not('api.installed')
def install():
    log('Installing Sojobo API')
    if not os.path.isdir(API_DIR):
        os.mkdir(API_DIR)
    install_api()
    set_state('api.installed')


@hook('upgrade-charm')
def upgrade_charm():
    log('Updating Sojobo API')
    install_api()
    set_state('api.installed')
    status_set('active', 'admin-password: {} api-key: {}'.format(db.get('password'), db.get('api-key')))


@when('api.installed', 'nginx.passenger.available')
@when_not('api.configured')
def configure_webapp():
    context = {'hostname': HOST, 'user': USER, 'rootdir': API_DIR, 'port': config()['port']}
    render('http.conf', '/etc/nginx/sites-enabled/sojobo.conf', context)
    open_port(config()['port'])
    service_restart('nginx')
    set_state('api.configured')
    status_set('blocked', 'Waiting for a connection with ArangoDB')


@when('config.changed', 'api.running')
def config_changed():
    context = {'hostname': HOST, 'user': USER, 'rootdir': API_DIR, 'port': config()['port']}
    close_port(config().previous('port'))
    open_port(config()['port'])
    render('http.conf', '/etc/nginx/sites-enabled/sojobo.conf', context)
    service_restart('nginx')


@when('leadership.is_leader')
@when_not('secrets.configured')
def set_secrets():
    api_key = leader_get().get('api-key', sha256(os.urandom(256)).hexdigest())
    password = leader_get().get('password', b64encode(os.urandom(18)).decode('utf-8'))
    leader_set({
        'api-key': api_key,
        'password': password
    })
    db.set('api-key', api_key)
    db.set('password', password)
    set_state('secrets.configured')


@when('api.configured')
@when_not('leadership.is_leader')
def set_secrets_local():
    db.set('api-key', leader_get()['api-key'])
    db.set('password', leader_get()['password'])


@when('api.configured', 'arango.available')
@when_not('api.running')
def connect_to_arango(arango):
    api_key = db.get('api-key')
    password = db.get('password')
    render('settings.py', '{}/settings.py'.format(API_DIR), {
        'API_KEY': api_key,
        'JUJU_ADMIN_USER': 'admin',
        'JUJU_ADMIN_PASSWORD': password,
        'SOJOBO_API_DIR': API_DIR,
        'LOCAL_CHARM_DIR': config()['charm-dir'],
        'SOJOBO_IP': 'http://{}'.format(HOST),
        'SOJOBO_USER': USER,
        'ARANGO_HOST': arango.host(),
        'ARANGO_PORT': arango.port(),
        'ARANGO_USER': arango.username(),
        'ARANGO_PASS': arango.password(),
        'ARANGO_DB': 'sojobo',
        'REPO_NAME': config()['github-repo'],
        'SOJOBO_API_PORT' : config()['port']
    })
    con = get_arangodb_connection(arango.host(), arango.port(), arango.username(), arango.password())
    sojobo_db = create_arangodb_database(con)
    create_arangodb_collections(sojobo_db)
    service_restart('nginx')
    status_set('active', 'admin-password: {} api-key: {}'.format(password, api_key))
    set_state('api.running')


@when('leadership.is_leader', 'api.running')
@when_not('admin.created')
def create_admin():
    if leader_get().get('admin') != 'Created':
        sys.path.append('/opt')
        from sojobo_api.api import w_datastore as datastore
        datastore.create_user('admin', 'admin')
        leader_set({'admin': 'Created'})
        status_set('active', 'admin-password: {} api-key: {}'.format(db.get('password'), db.get('api-key')))
        set_state('admin.created')
        datastore.set_user_state('admin', 'ready')
    else:
        leader_set({'admin': 'Created'})


@when('api.running')
@when_not('leadership.is_leader')
def status_update_not_leader():
    if leader_get().get('admin') != 'Created':
        status_set('blocked', 'error creating Tengu admin user')
    else:
        status_set('active', 'admin-password: {} api-key: {}'.format(db.get('password'), db.get('api-key')))


@when_not('arango.available')
def arango_db_removed():
    remove_state('api.running')
    remove_state('admin.created')
    status_set('blocked', 'Waiting for a connection with ArangoDB')


@when('sojobo.available', 'api.running')
def configure(sojobo):
    api_key = db.get('api-key')
    sojobo.configure('http://{}:{}'.format(config()['host'], config()['port']), API_DIR, api_key, db.get('password'), USER)


@when('proxy.available', 'api.running')
def configure_proxy(proxy):
    proxy.configure(config()['port'])
    set_state('api.proxy-configured')


@when('nginx_stats.connected', 'api.running')
def configure_nginx_stats(nginx_stats):
    nginx_stats.configure(config()['port'], 'nginx_status')
    set_state('api.nginx_stats-configured')


###############################################################################
# UTILS
###############################################################################
def mergecopytree(src, dst, symlinks=False, ignore=None):
    """Recursive copy src to dst, mergecopy directory if dst exists.
    OVERWRITES EXISTING FILES!!"""
    if not os.path.exists(dst):
        os.makedirs(dst)
        shutil.copystat(src, dst)
    lst = os.listdir(src)
    if ignore:
        excl = ignore(src, lst)
        lst = [x for x in lst if x not in excl]
    for item in lst:
        src_item = os.path.join(src, item)
        dst_item = os.path.join(dst, item)
        if symlinks and os.path.islink(src_item):
            if os.path.lexists(dst_item):
                os.remove(dst_item)
            os.symlink(os.readlink(src_item), dst_item)
        elif os.path.isdir(src_item):
            mergecopytree(src_item, dst_item, symlinks, ignore)
        else:
            shutil.copy2(src_item, dst_item)


def install_api():
    for pkg in ['Jinja2', 'flask', 'pyyaml', 'click', 'pygments','gitpython',
                'asyncio_extras', 'requests', 'juju==0.6.1', 'async_generator']:
        subprocess.check_call(['pip3', 'install', pkg])
    mergecopytree('files/sojobo_api', API_DIR)
    if not os.path.isdir('{}/files'.format(API_DIR)):
        os.mkdir('{}/files'.format(API_DIR))
    if not os.path.isdir('{}/bundle'.format(API_DIR)):
        os.mkdir('{}/bundle'.format(API_DIR))
    if not os.path.isdir('{}/log'.format(API_DIR)):
        os.mkdir('{}/log'.format(API_DIR))
    if not os.path.isdir('{}/backup'.format(API_DIR)):
        os.mkdir('{}/backup'.format(API_DIR))
    adduser(USER)
    if not os.path.isdir('/home/{}'.format(USER)):
        os.mkdir('/home/{}'.format(USER))
    chownr('/home/{}'.format(USER), USER, USER, chowntopdir=True)
    chownr(API_DIR, USER, GROUP, chowntopdir=True)
    service_restart('nginx')
    status_set('active', 'The Sojobo-api is installed')
    application_version_set('1.0.0')


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
    create_arangodb_collection(sojobo_db, "controllerAccess", edges=True)
    create_arangodb_collection(sojobo_db, "modelAccess", edges=True)


def has_collection(sojobo_db, collection_name):
    return collection_name in sojobo_db.collections
