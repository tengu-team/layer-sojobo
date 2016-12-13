import os
from subprocess import check_call, CalledProcessError
import unittest
import yaml
from api.w_juju import create_controller, get_controller_types, app_supports_series
from api import w_helpers as helpers


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


if __name__ == '__main__':
    unittest.main()
