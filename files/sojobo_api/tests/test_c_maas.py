# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902
import os
from subprocess import check_call, CalledProcessError
import unittest
from api.controller_maas import Token, get_supported_series, create_cloud_file, create_credentials_file, create_controller
import api.w_helpers as helpers


class Auth(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password


class TestMaas(unittest.TestCase):
    def setUp(self):
        self.token = Token('http://193.190.127.161/MAAS', Auth(helpers.get_user(), helpers.get_password()))

    def test_0_create_cloud_file(self):
        create_cloud_file('maas-unittesting', self.token.url)
        path = '/tmp/cloud.yaml'
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove('/tmp/cloud.yaml')

    def test_1_create_credentials_file(self):
        create_credentials_file('maas-unittesting', {'username': self.token.user, 'api_key': self.token.api_key})
        path = '/tmp/credentials.yaml'
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 0)
        os.remove('/tmp/credentials.yaml')

    def test_2_create_controller(self):
        try:
            check_call(['juju', 'destroy-controller', 'unittesting', '-y'])
        except CalledProcessError:
            pass
        try:
            check_call(['juju', 'remove-cloud', 'maas-unittesting'])
        except CalledProcessError:
            pass
        try:
            check_call(['juju', 'remove-credential', 'maas-unittesting', self.token.user])
        except CalledProcessError:
            pass
        try:
            create_controller('unittesting', self.token.url, {'username': self.token.user, 'api_key': self.token.api_key})
            self.assertTrue(True)
        except CalledProcessError:
            self.assertTrue(False)
        try:
            check_call(['juju', 'destroy-controller', 'unittesting', '-y'])
        except CalledProcessError:
            pass
        try:
            check_call(['juju', 'remove-cloud', 'maas-unittesting'])
        except CalledProcessError:
            pass
        try:
            check_call(['juju', 'remove-credential', 'maas-unittesting', self.token.user])
        except CalledProcessError:
            pass
        os.remove('/tmp/cloud.yaml')
        os.remove('/tmp/credentials.yaml')


    def test_3_get_supported_series(self):
        self.assertIsInstance(get_supported_series(), list)


if __name__ == '__main__':
    unittest.main()
