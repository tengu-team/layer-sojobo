# pylint: disable=c0111,c0301, E0611, E0401, c0103, w0511
#!/usr/bin/env python3
import json
from sojobo_api import settings
import pyArango.connection as pyArango #Via wheelhouse?


################################################################################
#                               DATABASE FUNCTIONS                             #
################################################################################


def get_arangodb_connection():
    """Creates entry point (connection) to work with ArangoDB."""
    url = 'http://' + settings.ARANGO_HOST + ':' + settings.ARANGO_PORT
    connection = pyArango.Connection(arangoURL=url,
                                     username=settings.ARANGO_USER,
                                     password=settings.ARANGO_PASS)
    return connection


def get_sojobo_database():
    """Returns the sojobo database, creates one if it doesn't exist yet."""
    con = get_arangodb_connection()
    if con.hasDatabase("sojobo"):
        return con["sojobo"]
    return con.createDatabase(name="sojobo")


def create_users_collection():
    """Creates the Document collection 'users' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "users"):
        db.createCollection(name="users")


def create_controllers_collection():
    """Creates the Document collection 'controllers' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "controllers"):
        db.createCollection(name="controllers")


def create_models_collection():
    """Creates the Document collection 'models' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "models"):
        db.createCollection(name="models")


def create_c_access_col():
    """Creates the Edge collection 'controllerAccess' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "controllerAccess"):
        db.createCollection(className="Edges", name="controllerAccess")


def create_m_access_col():
    """Creates the Edge collection 'modelAccess' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "modelAccess"):
        db.createCollection(className="Edges", name="modelAccess")


def has_collection(db, collection_name):
    return collection_name in db.collections


def execute_aql_query(aql, rawResults=False, **bindings):
    """Executes the given AQL query and returns its results.

    :param rawResults: Is default 'False' and will return ArangoDB object types
    like Documents. If it is 'True' then it will return a simple dict.

    :param bindings: The parameters of the AQL query. F.e. If you have one parameter
    @user in AQL query then this function will look like this: execute_aql_query(aql, user=value).
    If you have two parameters @user and @model then it will look like this:
    execute_aql_query(aql, user='admin', model='testmodel')."""
    db = get_sojobo_database()
    bind = {}
    for key in bindings:
        bind[key] = bindings[key]
    return db.AQLQuery(aql, rawResults=rawResults, bindVars=bind)


################################################################################
#                                USER FUNCTIONS                                #
################################################################################


def create_user(user_name):
    # Make sure that the collection 'users' exists.
    create_users_collection()
    # TODO: Maybe place this 'if' in w_juju?
    if not user_exists(user_name):
        user = {"_key": user_name,
                "name": user_name,
                "ssh-keys": [],
                "credentials": [],
                "state": "pending"}
        aql = "INSERT @user INTO users"
        execute_aql_query(aql, user=user)


def user_exists(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    # Returns an empty list if no user is found.
    user = execute_aql_query(aql, username=username)
    return  bool(user)


def get_user(username):
    """Returns the dict of a user."""
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return execute_aql_query(aql, rawResults=True, username=username)[0]


def get_user_doc(username):
    """Returns the Document of a user."""
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return  execute_aql_query(aql, username=username)[0]


def set_user_state(username, state):
    aql = 'UPDATE {_key: @username, state: @state} IN users'
    execute_aql_query(aql, username=username, state=state)


def get_user_state(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.state'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def get_ssh_keys(username):
    # TODO: Test.
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.ssh_keys'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def update_ssh_keys(username, ssh_keys):
    aql = 'UPDATE {_key: @username, ssh_keys: @ssh} IN users'
    execute_aql_query(aql, username=username, ssh=ssh_keys)


def add_credential(username, cred):
    # TODO: Omvormen naar AQL, methode hieronder is een poging.
    user = get_user_doc(username)
    if cred not in user['credentials']:
        user['credentials'].append(cred)
    user.save()


# def add_credential(username, cred):
#     aql = ('UPDATE "users/@username" WITH {'
#            'credentials: PUSH(doc.credentials, @cred, true)'
#            '} IN users')
#     execute_aql_query(aql, username=username, cred=cred)


def remove_credential(username, cred_name):
    # TODO: Omvormen naar AQL.
    user = get_user_doc(username)
    for cred in user['credentials']:
        if cred_name == cred['name']:
            user['credentials'].remove(cred)
    user.save()


def get_credentials(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.credentials'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def get_credential_keys(user):
    # TODO: To test.
    return [c['name'] for c in get_credentials(user)]


def get_all_users():
    """Returns a list with all users from the collection 'users'."""
    aql = "FOR u IN users RETURN u"
    return execute_aql_query(aql, rawResults=True)


def get_all_users_keys():
    """Returns a list with all usernames (keys) from the collection 'users'."""
    aql = "FOR u IN users RETURN u._key"
    return execute_aql_query(aql, rawResults=True)


def delete_user(username):
    """Remove user from collection 'users' and from access collections."""
    remove_user_c_access(username)
    remove_user_m_access(username)
    remove_user_u_col(username)


def remove_user_u_col(username):
    """Removes the user from the collection 'users'."""
    aql = 'REMOVE {_key: @user} IN users'
    execute_aql_query(aql, user=username)


def remove_user_c_access(username):
    """Removes every Edge from controllerAccess that contains given user."""
    u_id = "users/" + username
    aql = ('FOR edge in controllerAccess'
           'FILTER edge._to == @user'
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, user=u_id)


def remove_user_m_access(username):
    """Removes every Edge from modelAccess that contains given user."""
    u_id = "users/" + username
    aql = ('FOR edge in modelAccess'
           'FILTER edge._to == @user'
           'REMOVE edge in modelAccess')
    execute_aql_query(aql, user=u_id)


################################################################################
#                           CONTROLLER FUNCTIONS                               #
################################################################################


def create_controller(controller_name, c_type, region, cred_name):
    """Creates a controller using AQL."""
    create_controllers_collection()
    # TODO: Check if controller with that name already exists. In this layer?
    controller = {
        "_key": controller_name,
        "name": controller_name,
        "state": "accepted",
        "type": c_type,
        "models": [],
        "endpoints": [],
        "uuid": "",
        "ca-cert": "",
        "region": region,
        "default-credential": cred_name}
    aql = "INSERT @controller INTO controllers LET newController = NEW RETURN newController"
    execute_aql_query(aql, controller=controller)


def controller_exists(c_name):
    aql = 'FOR c IN controllers FILTER c._key == @cname RETURN c'
    # Returns an empty list if no controller is found.
    controller = execute_aql_query(aql, cname=c_name)
    return bool(controller)


def get_cloud_controllers(c_type):
    aql = 'FOR c IN controllers FILTER c.type == @cloud RETURN c'
    return execute_aql_query(aql, cloud=c_type)


def get_users_controller(c_name):
    """Returns a list with users of given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR edge IN controllerAccess '
           'FILTER edge._from == @controller '
           'LET u = '
               '(FOR u IN users FILTER u._id == edge._to RETURN u) '
           'RETURN MERGE(u)')
    return execute_aql_query(aql, rawResults=True, controller=c_id)


def get_controllers_user(username):
    u_id = "users/" + username
    aql = ('FOR edge IN controllerAccess '
           'FILTER edge._to == @user '
           'LET c = '
               '(FOR c IN controllers FILTER c._id == edge._from RETURN c) '
           'RETURN MERGE(c)')
    return execute_aql_query(aql, rawResults=True, user=u_id)


def get_controller(c_name):
    aql = 'FOR c IN controllers FILTER c._key == @controller RETURN c'
    return  execute_aql_query(aql, rawResults=True, controller=c_name)[0]


def get_controller_doc(c_name):
    """Returns the Document of a user from ArangoDB given the username (key)."""
    aql = 'FOR c IN controllers FILTER c._key == @cname RETURN c'
    return  execute_aql_query(aql, cname=c_name)[0]


def add_user_to_controller(c_name, username, access):
    """Creates or updates an Edge (relation) between a controller and a user."""
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ("UPSERT { _from: @controller, _to: @user }"
           "INSERT { _from: @controller, _to: @user, access: @access}"
           "UPDATE { access : @access } in hasAccess")
    execute_aql_query(aql, controller=c_id, user=u_id, access=access)


def set_controller_state(c_name, state, endpoints=None, uuid=None, ca_cert=None):
    # TODO: Erg dat bij error de None values worden gebruikt?
    aql = ('UPDATE @controller WITH {'
           'state: @state,'
           'endpoints: @endpoints,'
           'uuid: @uuid,'
           'ca_cert: @cacert'
           '} IN controllers')
    execute_aql_query(aql, controller=c_name, state=state, endpoints=endpoints,
                      uuid=uuid, cacert=ca_cert)


def destroy_controller(c_name):
    remove_edges_controller_access(c_name)
    remove_controller_c_col(c_name)


def remove_controller_c_col(c_name):
    """Removes the user from the collection 'users'."""
    aql = 'REMOVE {_key: @controller} IN controllers'
    execute_aql_query(aql, controller=c_name)


def remove_edges_controller_access(c_name):
    #TODO: Test.
    """Removes all Edges from the collection 'controllerAccess' that contain
    the given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR edge in controllerAccess '
           'FILTER edge._from == @controller '
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, controller=c_id)


def add_model_to_controller(c_name, m_name):
    # Add model to model collection
    # Get key of model
    # Add id to controllers
    model = create_model(m_name, state='Model is being deployed', uuid='')
    m_key = model["_key"]
    c_id = "controllers/" + c_name
    aql = ('LET doc = DOCUMENT(@controller) '
           'UPDATE doc WITH {'
           'models: PUSH(doc.models, @model, true)'
           '} IN controllers')
    execute_aql_query(aql, controller=c_id, model=m_key)


def get_controller_access(c_name, username):
    # TODO: Test.
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR edge in controllerAccess',
           'FILTER edge._from == @controller'
           'FILTER edge._to == @user'
           'RETURN edge.access')
    return execute_aql_query(aql, rawResults=True, controller=c_id, user=u_id)[0]


def set_controller_access(c_name, username, access):
    # TODO: Test
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR edge in controllerAccess',
           'FILTER edge._from == @controller'
           'FILTER edge._to == @user'
           'UPDATE edge WITH { access: @access } IN controllerAccess')
    return execute_aql_query(aql, controller=c_id, user=u_id, access=access)[0]


def get_controller_users(c_name):
    data = get_controller(c_name)
    return data['users']

def get_default_credential(c_name):
    controller = get_controller(c_name)
    return controller["default-credential"]

def get_all_controllers():
    create_controllers_collection()
    aql = 'FOR c in controllers RETURN c'
    return execute_aql_query(aql, rawResults=True)


def get_all_con_keys():
    """Returns a list with all the controllers their key."""
    create_controllers_collection()
    aql = 'FOR c in controllers RETURN c._key'
    return execute_aql_query(aql, rawResults=True)


# def get_all_models(c_name):
#     # TODO: Test
#     aql = ('FOR c in controllers'
#            'FILTER c._key == @controller'
#            'RETURN c.models')
#     return execute_aql_query(aql, rawResults=True, controller=c_name)

def get_all_models(c_name):
    # TODO: Test
    controller = get_controller(c_name)
    return controller["models"]


################################################################################
# MODEL FUNCTIONS
################################################################################

def create_model(m_name, state, uuid):
    create_models_collection()
    # TODO: Check if model with that name already exists. In this layer?
    model = {
        "name": m_name,
        "state": state,
        "uuid": uuid}
    aql = "INSERT @model INTO model LET newModel = NEW RETURN newModel"
    return execute_aql_query(aql, rawResults=True, model=model)


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


def set_model_state(c_name, m_name, state, credential=None, uuid=None):
    # TODO: Erg dat bij error de None values worden gebruikt?
    # TODO: Key in plaats van m_name
    aql = ('UPDATE @controller WITH {'
           'state: @state,'
           'endpoints: @endpoints,'
           'uuid: @uuid,'
           'ca_cert: @cacert'
           '} IN controllers')
    execute_aql_query(aql, controller=c_name, state=state, endpoints=endpoints,
                      uuid=uuid, cacert=ca_cert)


def check_model_state(m_name):
    # TODO: To test
    aql = ('FOR m IN models '
           'FILTER m._key == @model '
           'RETURN m.state')
    return execute_aql_query(aql, rawResults=True, model=m_name)[0]


def get_model_access(modelname, username):
    # TODO: Test.
    m_id = "models" + modelname
    u_id = "users/" + username
    aql = ('FOR edge in modelAccess',
           'FILTER edge._from == @model'
           'FILTER edge._to == @user'
           'RETURN edge.access')
    return execute_aql_query(aql, rawResults=True, model=m_id, user=u_id)[0]


def set_model_access(controller, model, user, access):
    con = connect_to_users()
    data = json.loads(con.get(user))
    acces_set = False
    for contr in data['controllers']:
        if contr['name'] == controller:
            for mod in contr['models']:
                if model == mod['name']:
                    mod['access'] = access
                    acces_set = True
    if not acces_set:
        for contr in data['controllers']:
            if contr['name'] == controller:
                contr['models'].append({'name': model, 'access': access})
    con.set(user, json.dumps(data))


def get_models_access(controller, user):
    data = get_user_doc(user)
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
