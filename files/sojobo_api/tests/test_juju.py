# pylint: disable=c0111,c0301,c0325
import os
from subprocess import CalledProcessError, check_call
import unittest
import yaml
from api.w_juju import create_controller, get_controller_types, app_supports_series, JuJu_Token, cloud_supports_series
from api.w_juju import authenticate, get_charm_dir, get_user, get_password
import api.controller_maas as maas
from tests.test_c_maas import cleanup_controller
from werkzeug.exceptions import Forbidden
from sojobo_api import get_api_dir


class Auth(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password


class TestJuJu(unittest.TestCase):
    def test_00_get_controller_types(self):
        self.assertIsInstance(get_controller_types(), dict)

    def test_01_app_supports_series(self):
        try:
            os.remove('{}/unittest/metadata.yaml'.format(get_charm_dir()))
        except OSError:
            pass
        try:
            os.rmdir('{}/unittest'.format(get_charm_dir()))
        except OSError:
            pass
        self.assertTrue(app_supports_series('mysql', 'trusty'))
        self.assertFalse(app_supports_series('mysql', 'blablabla'))
        os.mkdir('{}/unittest'.format(get_charm_dir()))
        with open('{}/unittest/metadata.yaml'.format(get_charm_dir()), 'w') as y_file:
            yaml.dump({'series': ['trusty', 'xenial']}, y_file, default_flow_style=True)
        self.assertTrue(app_supports_series('local:unittest', 'trusty'))
        self.assertFalse(app_supports_series('local:unittest', 'blablabla'))
        os.remove('{}/unittest/metadata.yaml'.format(get_charm_dir()))
        os.rmdir('{}/unittest'.format(get_charm_dir()))

    def test_02_create_controller(self):
        auth = Auth(get_user(), get_password())
        output = create_controller(JuJu_Token(auth), 'blablabla', 'shouldfail', 'shouldfail', {'should': 'fail'})
        self.assertTrue('Incorrect controller type' in output)
        cleanup_controller('maas', 'unittesting', auth.username)
        maas_token = maas.Token('http://193.190.127.161/MAAS', auth)
        try:
            create_controller(JuJu_Token(auth), 'maas', 'unittesting', 'http://193.190.127.161/MAAS',
                              {'username': auth.username, 'password': auth.password, 'api_key': maas_token.api_key})
            self.assertTrue(True)
        except CalledProcessError:
            self.assertTrue(False)

    def test_03_authenticate(self):
        auth = Auth(get_user(), get_password())
        api = 'api-key-unittesting'
        with open('{}/api-key'.format(get_api_dir()), 'w') as a_file:
            a_file.write('api-key-unittesting')
        self.assertRaises(Forbidden, lambda: authenticate('bad-api-key-unittesting', auth))
        self.assertIsInstance(authenticate(api, auth), JuJu_Token)
        self.assertRaises(Forbidden, lambda: authenticate(api, auth, 'nocontroller'))


    #def test_03_cloud_supports_series(self):
    #    with open('{}/api-key'.format(helpers.get_api_dir()), 'w') as a_file:
    #        a_file.write('api-key-unittesting')
    #    auth = Auth(helpers.get_user(), helpers.get_password())
    #    token = authenticate('api-key-unittesting', auth)
    #    token.c_token = maas.Token('http://193.190.127.161/MAAS', auth)
    #    self.assertTrue(cloud_supports_series(token, 'xenial'))
    #    self.assertFalse(cloud_supports_series(token, 'blablabla'))



if __name__ == '__main__':
    unittest.main()
