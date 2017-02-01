import sys
import os

INTERP = os.path.expanduser("/usr/bin/python3")
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())


from sojobo_api.sojobo_api import APP as application
