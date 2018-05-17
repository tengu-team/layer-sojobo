from subprocess import Popen
from flask import abort
from sojobo_api import settings
from sojobo_api.api import w_juju


def add_machine(username, password, controller_name, model_key, series,
                constraints, spec, company):
    '''
    This function start a background script which adds a machine to a model.
    '''
    cons = '' if constraints is None else str(constraints)
    specifications = '' if spec is None else str(spec)
    serie = '' if series is None else str(series)
    controller_key = w_juju.construct_controller_key(controller_name, company)
    Popen(["python3",
           "{}/scripts/add_machine.py".format(settings.SOJOBO_API_DIR),
           username, password, controller_key, model_key,
           serie, cons, specifications])


def get_machines(connection):
    result = {}
    for machine, data in connection.state.state.get('machine', {}).items():
        try:
            if data[0]['agent-status']['current'] == 'error' and \
               data[0]['addresses'] is None:
                result[machine] = {
                    'name': machine,
                    'Error': data[0]['agent-status']['message']
                    }
            if data[0] is None:
                result[machine] = {
                    'name': machine,
                    'instance-id': 'Unknown',
                    'ip': 'Unknown',
                    'series': 'Unknown',
                    'containers': 'Unknown',
                    'hardware-characteristics': 'Unknown'
                    }
            if 'lxd' in machine:
                result[machine.split('/')[0]].get('containers', []).append({
                    'name': machine, 'instance-id': data[0]['instance-id'],
                    'ip': get_machine_ip(data[0]), 'series': data[0]['series']
                })
            else:
                result[machine] = {
                    'name': machine,
                    'instance-id': data[0]['instance-id'],
                    'ip': get_machine_ip(data[0]),
                    'series': data[0]['series'],
                    'hardware-characteristics': data[0]['hardware-characteristics']
                }
        except KeyError:
            result[machine] = {
                'name': machine,
                'instance-id': 'Unknown',
                'ip': 'Unknown',
                'series': 'Unknown',
                'containers': 'Unknown',
                'hardware-characteristics': 'Unknown'
                }
    return [info for info in result.values()]


def get_machine(connection, machine):
    try:
        if not machine_exists(connection, machine):
            abort(404, 'The machine does not exist!')
        data = connection.state.state['machine']
        machine_data = data[machine][0]
        if machine_data['agent-status']['current'] == 'error' and \
           machine_data['addresses'] is None:
            result = {
                'name': machine,
                'Error': machine_data['agent-status']['message']
                }
            return result
        if machine_data is None:
            result = {
                'name': machine,
                'instance-id': 'Unknown',
                'ip': 'Unknown',
                'series': 'Unknown',
                'containers': 'Unknown',
                'hardware-characteristics': 'unknown'
                }
            return result
        containers = []
        if 'lxd' not in machine:
            lxd = []
            for key in data.keys():
                if key.startswith('{}/lxd'.format(machine)):
                    lxd.append(key)
            if lxd != []:
                for cont in lxd:
                    cont_data = data[cont][0]
                    ip = get_machine_ip(cont_data)
                    containers.append({
                        'name': cont,
                        'instance-id': cont_data['instance-id'],
                        'ip': ip,
                        'series': cont_data['series']
                        })
            mach_ip = get_machine_ip(machine_data)
            result = {
                'name': machine,
                'instance-id': machine_data['instance-id'],
                'ip': mach_ip,
                'series': machine_data['series'],
                'hardware-characteristics': machine_data['hardware-characteristics'],
                'containers': containers
                }
        else:
            mach_ip = get_machine_ip(machine_data)
            result = {
                'name': machine,
                'instance-id': machine_data['instance-id'],
                'ip': mach_ip,
                'series': machine_data['series'],
                'hardware-characteristics': machine_data['hardware-characteristics']
                }
    except KeyError:
        result = {
            'name': machine,
            'instance-id': 'Unknown',
            'ip': 'Unknown',
            'series': 'Unknown',
            'containers': 'Unknown',
            'hardware-characteristics': 'unknown'
            }
    return result


def machine_exists(connection, machine):
    return machine in connection.state.state.get('machine', {}).keys()


def get_machine_ip(machine_data):
    mach_ips = {'internal_ip': 'unknown', 'external_ip': 'unknown'}
    if machine_data['addresses'] is None:
        return mach_ips
    for machine in machine_data['addresses']:
        if machine['scope'] == 'public':
            mach_ips['external_ip'] = machine['value']
        elif machine['scope'] == 'local-cloud':
            mach_ips['internal_ip'] = machine['value']
    return mach_ips


def remove_machine(username, password, controller_name, model_key,
                   machine, company):
    controller_key = w_juju.construct_controller_key(controller_name, company)
    Popen(["python3",
           "{}/scripts/remove_machine.py".format(settings.SOJOBO_API_DIR),
           username, password, controller_key, model_key, machine])
