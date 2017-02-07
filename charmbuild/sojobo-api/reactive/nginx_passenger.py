import os
from charms.reactive import (
    set_state,
    when_not,
)

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render

import charms.apt


config = hookenv.config()


# handlers --------------------------------------------------------------------
@when_not('nginx.passenger.available', 'apt.installed.passenger',
          'apt.installed.nginx-extras')
def install_nginx():
    """ Install nginx
    """
    charms.apt.update()
    charms.apt.queue_install(['nginx-extras', 'passenger'])
    charms.apt.install_queued()

    if os.path.exists('/etc/nginx/nginx.conf'):
        os.remove('/etc/nginx/nginx.conf')
    render('nginx.conf.tmpl', '/etc/nginx/nginx.conf', context={})

    if os.path.exists('/etc/nginx/sites-enabled/default'):
        os.remove('/etc/nginx/sites-enabled/default')

    set_state('nginx.passenger.available')

# Example website.available reaction ------------------------------------------
"""
This example reaction for an application layer which consumes this nginx layer.
If left here then this reaction may overwrite your top-level reaction depending
on service names, ie., both nginx and ghost have the same reaction method,
however, nginx will execute since it's a higher precedence.
@when('nginx-passenger.available', 'website.available')
def configure_website(website):
    website.configure(port=config['port'])
"""
