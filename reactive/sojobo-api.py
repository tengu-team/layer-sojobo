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
from os.path import expanduser
import shutil
import tempfile
import subprocess
from time import sleep

# Charm pip dependencies
from charmhelpers.core import templating
from charmhelpers.core.hookenv import (
    status_set,
    log,
    config,
    open_port,
    close_port
)
from charmhelpers.core.host import service_restart, chownr, adduser
from charmhelpers.contrib.python.packages import pip_install

from charms.reactive import hook, when, when_not, set_state


API_DIR = '/opt/sojobo_api'
USER = 'ubuntu'
HOME = expanduser('~{}'.format(USER))
SSH_DIR = HOME + '/.ssh'
PORT = config()['port']


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


def install_api():
    # Install pip pkgs
    for pkg in ['Jinja2', 'Flask', 'pyyaml', 'click', 'pygments', 'apscheduler', 'gitpython']:
        pip_install(pkg)
    # Install The Sojobo API. Existing /etc files don't get overwritten.
    if os.path.isdir(API_DIR + '/etc'):
        t_etc_dir = tempfile.mkdtemp()
        mergecopytree(API_DIR + '/etc', t_etc_dir)
        mergecopytree('files/sojobo_api', API_DIR)
        mergecopytree(t_etc_dir, API_DIR + '/etc')
    else:
        mergecopytree('files/sojobo_api', API_DIR)
    os.mkdir('{}/files'.format(API_DIR))
    render_api_systemd_template()
    # USER should get all access rights.
    adduser(USER)
    chownr(API_DIR, USER, USER, chowntopdir=True)
    subprocess.check_call([u'systemctl', 'enable', 'sojobo-api'])
    generate_api_key()
    restart_api()
    status_set('active', 'Sojobo API is running')


# Creates the service file required to run the api as a service
def render_api_systemd_template():
    appconf = config()
    env_vars = [
        "JUJU_ADMIN_USER=admin",
        "JUJU_ADMIN_PASSWORD={}".format(appconf['juju-admin-password']),
        "SOJOBO_API_DIR={}".format(API_DIR),
        "SOJOBO_API_PORT={}".format(PORT),
        "LOCAL_CHARM_DIR={}".format(appconf['charm-dir']),
        "PYTHONPATH={}".format(API_DIR)
    ]
    flags = appconf['feature-flags'].replace(' ', '')
    flags = [x for x in flags.split(',') if x != '']
    templating.render(
        source='flask-app.service',
        target='/etc/systemd/system/sojobo-api.service',
        context={
            'description': "The Sojobo API",
            'application_dir': API_DIR,
            'application_path': "{}/sojobo_api.py".format(API_DIR),
            'user': USER,
            'flags': flags,
            'env_vars': env_vars,
        }
    )
    subprocess.check_call(['systemctl', 'daemon-reload'])


def restart_api():
    close_port(PORT)
    service_restart('sojobo-api')
    # Following is to make sure charm crashes when service fails to get up
    sleep(5)
    subprocess.check_call(['systemctl', 'is-active', 'sojobo-api'])
    open_port(PORT)


# Handeling changed configs
@when('api.installed')
@when('config.changed.feature-flags')
def feature_flags_changed():
    render_api_systemd_template()
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
