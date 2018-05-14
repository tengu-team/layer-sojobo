'''
.. module: user_manager
'''
from subprocess import Popen
from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore


class UserObject(object):

    def __init__(self, username, password, juju_username,
                 controller_access=None, model_access=None, company=None,
                 company_access=None, ssh_keys=None, credentials=None):
        """ This will create a user Object

        :param str username: The username used to login to the Tengu
            environment.
        :param str password: The pasword used to login to the Tengu
            environment.
        :param str juju_username: The username as it is known by JUJU, not the
            same as the username to log in.
        :param str controller_access: The access level on a given
            controller(optional).
        :param str model_access: The access level on a given model(optional).
        :param str company: The name of the company, the user belongs to
            (optional).
        :param str company_access: The access level for a user in his company
            (optional).
        :param list ssh_keys: A list of a user's ssh keys (optional).
        :param list credentials: A list of a user's credentials (optional).
        """
        self.username = username
        self.password = password
        self.juju_username = juju_username
        self.controller_access = controller_access
        self.model_access = model_access
        self.company = company
        self.company_access = company_access
        self.ssh_keys = ssh_keys
        self.credentials = credentials


def change_user_password(juju_username, new_password, controller_name):
    """
    This function will change the user his password on the given controller.

    :param juju_username: The username as it is known by JUJU, not the same as
        the username to log in.
    :type juju_username: str.
    :param new_password: The new password for the provided user.
    :type new_password: str.
    :param controller_name: The name of the controller where the password needs
        to be changed
    :type controller_name: str.
    """
    Popen(["python3",
           "{}/scripts/change_password.py".format(settings.SOJOBO_API_DIR),
           controller_name, juju_username, new_password])


def user_exists(username):
    return datastore.user_exists(username)
