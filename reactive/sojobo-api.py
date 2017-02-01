#!/usr/bin/env python3
# Copyright (C) 2016  Qrama
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
# pylint: disable=c0111,c0103,c0301

from hashlib import sha256
import os
import shutil
import subprocess
# Charm pip dependencies
from charmhelpers.core.templating import render
from charmhelpers.core.hookenv import status_set, log, config, open_port, close_port, unit_public_ip
from charmhelpers.core.host import service_restart, chownr, adduser
from charmhelpers.contrib.python.packages import pip_install

from charms.reactive import hook, when, when_not, set_state

API_DIR = config()['api-dir']
USER = config()['api-user']
GROUP = config()['nginx-group']
PORT = 443 if config()['port'] == 443 else 80
HOST = config()['host'] if config()['host'] != '127.0.0.1' else unit_public_ip()
###############################################################################
# INSTALLATION AND UPGRADES
###############################################################################
@when('juju.installed')
@when_not('api.installed')
def install():
    log('Installing Sojobo API')
    install_api()
    set_state('api.installed')


@hook('upgrade-charm')
def upgrade_charm():
    log('Updating Sojobo API')
    install_api()
    set_state('api.installed')


@when('api.installed', 'nginx.passenger.available')
def configure_webapp():
    if PORT == 443:
        render_https()
    else:
        render_http()
    restart_api()
    status_set('active', 'The Sojobo-api is running')


def install_api():
    # Install pip pkgs
    for pkg in ['Jinja2', 'Flask', 'pyyaml', 'click', 'pygments', 'apscheduler', 'gitpython']:
        pip_install(pkg)
    mergecopytree('files/sojobo_api', API_DIR)
    os.mkdir('{}/files'.format(API_DIR))
    render('settings.py', '{}/settings.py'.format(API_DIR), {'JUJU_ADMIN_USER': 'admin',
                                                             'JUJU_ADMIN_PASSWORD': config()['juju-admin-password'],
                                                             'SOJOBO_API_DIR': API_DIR,
                                                             'LOCAL_CHARM_DIR': config()['charm-dir'],
                                                             'SOJOBO_IP': HOST})
    adduser(USER)
    chownr(API_DIR, USER, GROUP, chowntopdir=True)
    generate_api_key()
    status_set('active', 'The Sojobo-api is installed')


def render_http():
    context = {'hostname': HOST, 'user': USER, 'rootdir': API_DIR}
    render('sojobo-http-80.conf', '/etc/nginx/sites-enabled/sojobo.conf', context)


def render_https():
    return None


def restart_api():
    close_port(PORT)
    service_restart('nginx')
    subprocess.check_call(['service', 'nginx', 'status'])
    open_port(PORT)


# Handeling changed configs
@when('api.installed', 'config.changed')
def feature_flags_changed():
    configure_webapp()
    restart_api()


@when('sojobo.available')
def configure(sojobo):
    with open("/{}/api-key".format(API_DIR), "r") as key:
        sojobo.configure(PORT, key)
###############################################################################
# UTILS
###############################################################################
def mergecopytree(src, dst, symlinks=False, ignore=None):
    """"Recursive copy src to dst, mergecopy directory if dst exists.
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


def generate_api_key():
    with open("/{}/api-key".format(API_DIR), "w") as key:
        key.write(sha256(os.urandom(256)).hexdigest())
