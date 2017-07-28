# pylint: disable=c0111,c0301, E0611, E0401
#!/usr/bin/env python3
import redis
import json
from sojobo_api import settings
################################################################################
# Database Fucntions
################################################################################
def connect_to_controllers():
    con = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, charset="utf-8", decode_responses=True, db=10)
    return con


def connect_to_users():
    con = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, charset="utf-8", decode_responses=True, db=11)
    return con
################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name, ssh_key=None):
    if not user_name in get_all_users():
        user = {'name' : user_name,
                'access': [],
                'ssh_keys': [ssh_key],
                'credentials': [],
                'active': True}
        con = connect_to_users()
        json_user = json.dumps(user)
        con.set(user_name, json_user)


def disable_user(user):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    data['active'] = False
    data['access'] = []
    json_data = json.dumps(data)
    con.set(user, json_data)


def enable_user(user):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    data['active'] = True
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_user(user):
    con = connect_to_users()
    data = con.get(user)
    return json.loads(data)


def add_ssh_key(user, ssh_key):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    keys = data['ssh_keys']
    keys.append(ssh_key)
    data['ssh_keys'] = keys
    json_data = json.dumps(data)
    con.set(user, json_data)


def remove_ssh_key(user, ssh_key):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    keys = data['ssh_keys']
    if ssh_key in keys:
        keys.remove(ssh_key)
    data['ssh_keys'] = keys
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_ssh_keys(user):
    con = connect_to_users()
    data = con.get(user)
    return json.loads(data)['ssh_keys']


def add_credential(user, cred):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    creds = data['credentials']
    creds.append(cred)
    data['credentials'] = creds
    json_data = json.dumps(data)
    con.set(user, json_data)


def remove_credential(user, cred):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    creds = data['credentials']
    if cred in creds:
        creds.remove(cred)
    data['credentials'] = creds
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_credentials(user):
    con = connect_to_users()
    data = con.get(user)
    return json.loads(data)['credentials']


def get_credential_keys(user):
    creds = get_credentials(user)
    cred_keys = []
    for cred in creds:
        cred_keys.append(cred['name'])
    return cred_keys


def get_all_users():
    con = connect_to_users()
    return con.keys()
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name, c_type):
    con = connect_to_controllers()
    if controller_name in con.keys():
        return False
    else:
        controller = {'name' : controller_name, 'users': [], 'type' : c_type, 'models' : []}
        json_data = json.dumps(controller)
        con.set(controller_name, json_data)
        return True


def destroy_controller(c_name):
    con = connect_to_controllers()
    con.delete(c_name)
    for user in get_all_users():
        remove_controller(c_name, user)


def remove_controller(c_name, user):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    acc_list = data['access']
    for acc in acc_list:
        if list(acc.keys())[0] == c_name:
            acc_list.remove(acc)
    data['access'] = acc_list
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_controller(c_name):
    con = connect_to_controllers()
    data = con.get(c_name)
    return json.loads(data)


def add_model_to_controller(c_name, m_name):
    model = {}
    model[m_name] = "Model is being deployed"
    con = connect_to_controllers()
    data = con.get(c_name)
    controller = json.loads(data)
    model_list = controller['models']
    model_list.append(model)
    controller['models'] = model_list
    json_data = json.dumps(controller)
    con.set(c_name, json_data)


def set_model_state(c_name, m_name, state):
    con = connect_to_controllers()
    data = con.get(c_name)
    controller = json.loads(data)
    new_models = []
    for mod in controller['models']:
        if list(mod.keys())[0] == m_name:
            new_mod = {}
            new_mod[m_name] = state
            mod = new_mod
        new_models.append(mod)
    controller['models'] = new_models
    json_data = json.dumps(controller)
    con.set(c_name, json_data)


def check_model_state(c_name, m_name):
    con = get_controller(c_name)
    for mod in con['models']:
        if list(mod.keys())[0] == m_name:
            return mod[m_name]
    return 'error'


def get_controller_access(c_name, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == c_name:
            return acc[c_name]['access']


def set_controller_access(c_name, user, access):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == c_name:
            acc[c_name]['access'] = access
        new_access.append(acc)
    data['access'] = new_access
    json_data = json.dumps(data)
    con.set(c_name, json_data)


def add_user_to_controller(c_name, user, access):
    con = connect_to_controllers()
    con_data = con.get(c_name)
    data = json.loads(con_data)
    users = data['users']
    users.append(user)
    data['users'] = users
    json_data = json.dumps(data)
    con.set(c_name, json_data)
    con2 = connect_to_users()
    user_data = con2.get(user)
    data2 = json.loads(user_data)
    new_access = data2['access']
    new_cont= {c_name:{'access' : access, 'models' : []}}
    new_access.append(new_cont)
    data2['access'] = new_access
    json_data2 = json.dumps(data2)
    con2.set(user, json_data2)


def remove_user_from_controller(c_name, user):
    con = connect_to_controllers()
    con_data = con.get(c_name)
    data = json.loads(con_data)
    users = data['users']
    if user in users:
        users.remove(user)
    data['users'] = users
    json_data = json.dumps(data)
    con.set(c_name, json_data)


def get_controller_users(c_name):
    con = connect_to_controllers()
    con_data = con.get(c_name)
    data = json.loads(con_data)
    result = []
    for user in data['users']:
        user = get_user(user)
        result.append(user)
    return result


def get_all_controllers():
    con = connect_to_controllers()
    return con.keys()
################################################################################
# MODEL FUNCTIONS
################################################################################
def delete_model(controller, model):
    users = get_all_users()
    for user in users:
        remove_model(controller, model, user)


def remove_model(controller, model, user):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            acc[controller]['models'] = models
        new_access.append(acc)
    data['access'] = new_access
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_model_access(controller, model, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for mod in models:
                if list(mod.keys())[0] == model:
                    return mod[model]
    return None


def set_model_access(controller, model, user, access):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            new_model = {model: access}
            models.append(new_model)
            acc[controller]['models'] = models
        new_access.append(acc)
    data['access'] = new_access
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_models_access(controller, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            return acc[controller]['models']


def remove_models_access(controller, user):
    con = connect_to_users()
    user_data = con.get(user)
    data = json.loads(user_data)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            acc[controller]['models'] = []
        new_access.append(acc)
    data['access'] = new_access
    json_data = json.dumps(data)
    con.set(user, json_data)


def get_users_model(controller, model):
    users = get_all_users()
    result = []
    for user in users:
        mod_acc = get_model_access(controller, model, user)
        if not mod_acc is None:
            acc = {'user' : user, 'access' : mod_acc}
            result.append(acc)
    return result
