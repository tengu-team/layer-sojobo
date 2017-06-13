#!/usr/bin/env python3
# Copyright (C) 2017  Qrama
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
# pylint: disable=c0111,c0301,c0325,w0406,e0401
import subprocess
import pip

if __name__ == '__main__':
    installed_packages = pip.get_installed_distributions()
    flat_installed_packages = [package.project_name for package in installed_packages]
    if not 'psutil' in flat_installed_packages:
        subprocess.check_call(['pip', 'install', 'psutil', '-q', '-q', '-q'])
    import psutil
    cores = psutil.cpu_count()
    print(cores)
