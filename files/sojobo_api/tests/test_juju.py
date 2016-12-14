# pylint: disable=c0111,c0301,c0325
import os
import unittest
import yaml
from api.w_juju import create_controller, get_controller_types, app_supports_series, JuJu_Token, cloud_supports_series
from api.w_juju import authenticate
import api.controller_maas as maas
from api import w_helpers as helpers
from werkzeug.exceptions import Forbidden


class Auth(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password


class TestJuJu(unittest.TestCase):
    def test_00_get_controller_types(self):
        self.assertIsInstance(get_controller_types(), dict)

    def test_01_app_supports_series(self):
        try:
            os.remove('{}/unittest/metadata.yaml'.format(helpers.get_charm_dir()))
        except OSError:
            pass
        try:
            os.rmdir('{}/unittest'.format(helpers.get_charm_dir()))
        except OSError:
            pass
        self.assertTrue(app_supports_series('mysql', 'trusty'))
        self.assertFalse(app_supports_series('mysql', 'blablabla'))
        os.mkdir('{}/unittest'.format(helpers.get_charm_dir()))
        with open('{}/unittest/metadata.yaml'.format(helpers.get_charm_dir()), 'w') as y_file:
            yaml.dump({'series': ['trusty', 'xenial']}, y_file, default_flow_style=True)
        self.assertTrue(app_supports_series('local:unittest', 'trusty'))
        self.assertFalse(app_supports_series('local:unittest', 'blablabla'))
        os.remove('{}/unittest/metadata.yaml'.format(helpers.get_charm_dir()))
        os.rmdir('{}/unittest'.format(helpers.get_charm_dir()))

    def test_02_authenticate(self):
        auth = Auth(helpers.get_user(), helpers.get_password())
        api = 'api-key-unittesting'
        with open('{}/api-key'.format(helpers.get_api_dir()), 'w') as a_file:
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
    unittest.main(buffer=True)
