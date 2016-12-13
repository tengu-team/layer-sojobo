# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902
import os
from subprocess import check_output, CalledProcessError

from api import w_helpers as helpers


def get_tests():
    test_c_list = []
    test_a_list = []
    for f_path in os.listdir('{}/tests'.format(helpers.get_api_dir())):
        if '.pyc' not in f_path:
            if 'test_a_' in f_path:
                test_a_list.append(f_path)
            elif 'test_c_' in f_path:
                test_c_list.append(f_path)
    test_c_list.append('test_juju.py')
    return test_c_list + test_a_list


if __name__ == '__main__':
    tests = get_tests()
    n_tests = len(tests)
    failed = []
    for count, test in enumerate(tests):
        print('\033[1mEXECUTING {}/{}: {}\033[0m'.format(count+1, n_tests, test))
        try:
            print(check_output((['python3', '{}/tests/{}'.format(helpers.get_api_dir(), test), '-v'])))
        except CalledProcessError:
            failed.append(test)
    print('\n')
    if len(failed) == 0:
        print('\033[92m\033[1mSUCCESS\033[0m: All tests passed: well done!')
    else:
        print ('\033[91m\033[1mFAILURE:\033[0m the following components have failed: {}'.format(failed))
