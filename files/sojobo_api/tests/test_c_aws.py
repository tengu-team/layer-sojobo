# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902
import os
from subprocess import check_call, CalledProcessError
import unittest
from api.controller_aws import Token, get_supported_series, create_credentials_file, create_controller


class TestAWS(unittest.TestCase):
    def setUp(self):
        self.token = Token('url', None, 'access_key', 'secret_key')

    def test_1_create_credentials_file(self):
        create_credentials_file('aws-unittesting', self.token)
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
            check_call(['juju', 'remove-credential', 'aws-unittesting', self.token.user])
        except CalledProcessError:
            pass
        try:
            create_controller('unittesting', self.token)
            self.assertTrue(True)
        except CalledProcessError:
            self.assertTrue(False)
        try:
            check_call(['juju', 'destroy-controller', 'unittesting', '-y'])
        except CalledProcessError:
            pass
        try:
            check_call(['juju', 'remove-credential', 'aws-unittesting', self.token.user])
        except CalledProcessError:
            pass
        os.remove('/tmp/credentials.yaml')


    def test_3_get_supported_series(self):
        self.assertIsInstance(get_supported_series(), list)


if __name__ == '__main__':
    unittest.main()
