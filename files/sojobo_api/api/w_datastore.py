# pylint: disable=c0111,c0301, E0611, E0401
#!/usr/bin/env python3
import json
import redis
from sojobo_api import settings
################################################################################
# Database Fucntions
################################################################################
def connect_to_controllers():
    return redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        charset="utf-8",
        decode_responses=True,
        db=10
    )


def connect_to_users():
    return redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        charset="utf-8",
        decode_responses=True,
        db=11
    )
################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name):
    if not user_name in get_all_users():
        user = {'name' : user_name,
                'controllers': [],
                'ssh-keys': [],
                'credentials': [],
                'active': True}
        con = connect_to_users()
        con.set(user_name, json.dumps(user))


def disable_user(user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    data['active'] = False
    data['controllers'] = []
    con.set(user, json.dumps(data))


def enable_user(user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    data['active'] = True
    con.set(user, json.dumps(data))


def get_user(user):
    con = connect_to_users()
    return json.loads(con.get(user))


def add_ssh_key(user, ssh_key):
    con = connect_to_users()
    data = json.loads(con.get(user))
    if ssh_key not in data['ssh-keys']:
        data['ssh-keys'].append(ssh_key)
    con.set(user, json.dumps(data))


def remove_ssh_key(user, ssh_key):
    con = connect_to_users()
    data = json.loads(con.get(user))
    if ssh_key in data['ssh-keys']:
        data['ssh-keys'].remove(ssh_key)
    con.set(user, json.dumps(data))


def get_ssh_keys(user):
    con = connect_to_users()
    return json.loads(con.get(user))['ssh-keys']


def add_credential(user, cred):
    con = connect_to_users()
    data = json.loads(con.get(user))
    if cred not in data['credentials']:
        data['credentials'].append(cred)
    con.set(user, json.dumps(data))


def remove_credential(user, cred):
    con = connect_to_users()
    data = json.loads(con.get(user))
    if cred in data['credentials']:
        data['credentials'].remove(cred)
    con.set(user, json.dumps(data))


def get_credentials(user):
    con = connect_to_users()
    return json.loads(con.get(user))['credentials']


def get_credential_keys(user):
    return [c['name'] for c in get_credentials(user)]


def get_all_users():
    con = connect_to_users()
    return con.keys()
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name, c_type, region):
    con = connect_to_controllers()
    if controller_name in con.keys():
        return False
    else:
        controller = {
            'name' : controller_name,
            'state': 'accepted',
            'users': [],
            'type' : c_type,
            'models' : [],
            'endpoints': [],
            'uuid': '',
            'ca-cert': '',
            'region': region
        }
        con.set(controller_name, json.dumps(controller))
        return True


def set_controller_state(controller, state, endpoints=None, uuid=None, ca_cert=None):
    con = connect_to_controllers()
    data = json.loads(con.get(controller))
    data['state'] = state
    if endpoints:
        data['endpoints'] = endpoints
    if uuid:
        data['uuid'] = uuid
    if ca_cert:
        data['ca-cert'] = ca_cert
    con.set(controller, json.dumps(data))


def destroy_controller(c_name):
    con = connect_to_controllers()
    con.delete(c_name)
    for user in get_all_users():
        remove_controller(c_name, user)


def remove_controller(c_name, user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for controller in data['controllers']:
        if controller['name'] == c_name:
            data['controllers'].remove(controller)
            break
    con.set(user, json.dumps(data))


def get_controller(c_name):
    con = connect_to_controllers()
    return json.loads(con.get(c_name))


def add_model_to_controller(c_name, m_name):
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    exists = False
    for model in data['models']:
        if model['name'] == m_name:
            exists = True
            break
    if not exists:
        data['models'].append({'name': m_name, 'status': 'Model is being deployed', 'uuid': ''})
    con.set(c_name, json.dumps(data))


def set_model_state(c_name, m_name, status, uuid=None):
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    for model in data['models']:
        if model['name'] == m_name:
            model['status'] = status
            if uuid:
                model['uuid'] = uuid
            break
    con.set(c_name, json.dumps(data))


def check_model_state(c_name, m_name):
    con = get_controller(c_name)
    for mod in con['models']:
        if mod['name'] == m_name:
            return mod['status']
    return 'error'


def get_controller_access(c_name, user):
    for controller in get_user(user)['controllers']:
        if controller['name'] == c_name:
            return controller['access']


def set_controller_access(c_name, user, access):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for controller in data['controllers']:
        if controller['name'] == c_name:
            controller['access'] = access
            break
    con.set(user, json.dumps(data))
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    for usr in data['users']:
        if usr['name'] == user:
            usr['access'] = access
            break
    con.set(c_name, json.dumps(data))


def add_user_to_controller(c_name, user, access):
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    c_type = data['type']
    exists = False
    for usr in data['users']:
        if usr['name'] == user:
            exists = True
            usr['name']['access'] = access
            break
    if not exists:
        data['users'].append({'name': user, 'access': access})
    con.set(c_name, json.dumps(data))
    con = connect_to_users()
    data = json.loads(con.get(user))
    for controller in data['controllers']:
        if controller['name'] == c_name:
            controller['access'] = access
            exists = True
            break
    if not exists:
        data['controllers'].append({
            'access' : access,
            'name': c_name,
            'models' : [],
            'type': c_type
        })
    con.set(user, json.dumps(data))


def remove_user_from_controller(c_name, user):
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    if user in data['users']:
        data['users'].remove(user)
    con.set(c_name, json.dumps(data))
    con = connect_to_users()
    data = json.loads(con.get(user))
    for controller in data['controllers']:
        if controller['name'] == c_name:
            data['controllers'].remove(controller)
            break
    con.set(user, json.dumps(data))


def get_controller_users(c_name):
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    return [get_user(u) for u in data['users']]


def get_all_controllers():
    con = connect_to_controllers()
    return con.keys()


def get_all_models(controller):
    con = connect_to_controllers()
    data = json.loads(con.get(controller))
    return data['models']
################################################################################
# MODEL FUNCTIONS
################################################################################
def delete_model(controller, model):
    con = connect_to_controllers()
    data = json.loads(con.get(controller))
    for mod in data['models']:
        if mod['name'] == model:
            data['models'].remove(mod)
            break
    con.set(controller, json.dumps(data))
    for user in get_all_users():
        remove_model(controller, model, user)


def remove_model(controller, model, user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for contr in data['controllers']:
        if contr['name'] == controller:
            for mod in contr['models']:
                if mod['name'] == model:
                    contr['models'].remove(mod)
                    break
            break
    con.set(user, json.dumps(data))


def get_model_access(controller, model, user):
    data = get_user(user)
    for con in data['controllers']:
        if con['name'] == controller:
            for mod in con['models']:
                if mod['name'] == model:
                    return mod['access']


def set_model_access(controller, model, user, access):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for contr in data['controllers']:
        if contr['name'] == controller:
            if model not in contr['models']:
                contr['models'].append({'name': model, 'access': access})
            else:
                for mod in contr['models']:
                    if mod['name'] == model:
                        mod['access'] = access
                    break
            break
    con.set(user, json.dumps(data))


def get_models_access(controller, user):
    data = get_user(user)
    for con in data['controllers']:
        if con['name'] == controller:
            return con['models']


def remove_models_access(controller, user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for con in data['controllers']:
        if con['name'] == controller:
            con['models'] = []
            break
    con.set(user, json.dumps(data))


def get_model(controller, model):
    data = get_controller(controller)
    for mod in data['models']:
        if mod['name'] == model:
            return mod


def get_users_model(controller, model):
    return [u for u in get_all_users() if get_model_access(controller, model, u) is not None]
