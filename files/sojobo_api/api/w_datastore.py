# pylint: disable=c0111,c0301, E0611, E0401, c0103, w0511, c0330
#!/usr/bin/env python3
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
    #TODO: Naar reactive, naam settings.py
    if con.hasDatabase("sojobo"):
        return con["sojobo"]
    return con.createDatabase(name="sojobo")


def execute_aql_query(aql, rawResults=False, **bindings):
    """Executes the given AQL query and returns its results.

    :param rawResults: Is default 'False' and will return ArangoDB object types
    like Documents. If it is 'True' then it will return a simple dict.

    :param bindings: The parameters of the AQL query. F.e. If you have one parameter
    @user in AQL query then this function will look like this: execute_aql_query(aql, user='admin').
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


def create_user(username):
    user = {"_key": username,
            "name": username,
            "ssh_keys": [],
            "credentials": [],
            "state": "pending"}
    aql = "INSERT @user INTO users"
    execute_aql_query(aql, user=user)


def user_exists(username):
    aql = 'FOR u in users FILTER u._key == @username RETURN u'
    # Returns an empty list if no user is found.
    user = execute_aql_query(aql, username=username)
    return bool(user)


def get_user(username):
    """Returns the dict of a user."""
    u_id = "users/" + username
    aql = 'RETURN DOCUMENT(@u_id)'
    return execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def get_all_users():
    """Returns a list with all users from the collection 'users'."""
    aql = "FOR u IN users RETURN u"
    return execute_aql_query(aql, rawResults=True)


def get_user_doc(username):
    # TODO: Als credentials methoden werken dan is deze overbodig.
    """Returns the Document of a user."""
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return  execute_aql_query(aql, username=username)[0]


def get_user_info(username):
    """Returns info of the given user, including which controllers and models
    that the user has access to."""
    u_id = "users/" + username
    aql = ('LET u = DOCUMENT(@user) '
           'LET controllers = '
                '(FOR controller, cEdge IN 1..1 INBOUND u._id controllerAccess '
                    'LET models = '
                        '(FOR model, mEdge in 1..1 INBOUND u._id modelAccess '
                            'FILTER model._key in controller.models '
                            'RETURN {name: model.name, '
                                    'access: mEdge.access}) '
                    'RETURN {name: controller.name, '
                            'type: controller.type, '
                            'access: cEdge.access, '
                            'models: models}) '
            'RETURN {name: u.name, '
                    'credentials: u.credentials, '
                    'ssh_keys: u.ssh_keys, '
                    'controllers: controllers} ')
    return  execute_aql_query(aql, rawResults=True, user=u_id)[0]


def get_user_state(username):
    u_id = "users/" + username
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.state'
    return  execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def set_user_state(username, state):
    aql = 'UPDATE {_key: @username, state: @state} IN users'
    execute_aql_query(aql, username=username, state=state)


def get_ssh_keys(username):
    u_id = "users/" + username
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.ssh_keys'
    return  execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def update_ssh_keys(username, ssh_keys):
    aql = 'UPDATE {_key: @username, ssh_keys: @ssh} IN users'
    execute_aql_query(aql, username=username, ssh=ssh_keys)


def add_credential(username, cred):
    # TODO: Omvormen naar AQL.
    user = get_user_doc(username)
    if cred not in user['credentials']:
        user['credentials'].append(cred)
    user.save()


def get_credentials(username):
    u_id = "users/" + username
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.credentials'
    return  execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def get_credential_keys(user):
    return [c['name'] for c in get_credentials(user)]


def remove_credential(username, cred_name):
    # TODO: Omvormen naar AQL.
    user = get_user_doc(username)
    for cred in user['credentials']:
        if cred_name == cred['name']:
            user['credentials'].remove(cred)
    user.save()


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
    aql = ('FOR edge in controllerAccess '
           'FILTER edge._to == @user '
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, user=u_id)


def remove_user_m_access(username):
    """Removes every Edge from modelAccess that contains given user."""
    u_id = "users/" + username
    aql = ('FOR edge in modelAccess '
           'FILTER edge._to == @user '
           'REMOVE edge in modelAccess')
    execute_aql_query(aql, user=u_id)


################################################################################
#                           CONTROLLER FUNCTIONS                               #
################################################################################


def create_controller(controller_name, c_type, region, cred_name):
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
    return execute_aql_query(aql, controller=controller)


def create_manual_controller(name, c_type, url):
    controller = {
        "_key": name,
        "name": name,
        "state": "accepted",
        "type": c_type,
        "models": [],
        "endpoints": [],
        "uuid": "",
        "ca-cert": "",
        "url": url}
    aql = "INSERT @controller INTO controllers LET newController = NEW RETURN newController"
    return execute_aql_query(aql, controller=controller)


def controller_exists(c_name):
    aql = 'FOR c in controllers FILTER c._key == @c_name RETURN c'
    # Returns an empty list if no controller is found.
    controller = execute_aql_query(aql, c_name=c_name)
    return bool(controller)


def get_controller(c_name):
    """Returns the dict of a controller."""
    c_id = "controllers/" + c_name
    aql = 'RETURN DOCUMENT(@c_id)'
    # TODO: Is [0] nodig?
    return execute_aql_query(aql, rawResults=True, c_id=c_id)[0]


def get_all_controllers():
    aql = 'FOR c in controllers RETURN c'
    return execute_aql_query(aql, rawResults=True)


def get_all_controllers_names():
    aql = 'FOR c in controllers RETURN c._key'
    return execute_aql_query(aql, rawResults=True)


def get_cloud_controllers(c_type):
    aql = 'FOR c IN controllers FILTER c.type == @cloud RETURN c._key'
    return execute_aql_query(aql, rawResults=True, cloud=c_type)


def get_users_controller(c_name):
    """Returns a list with users and access of given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR u, cEdge IN 1..1 OUTBOUND @c_id controllerAccess '
               'RETURN {name: u.name, access: cEdge.access}')
    return execute_aql_query(aql, rawResults=True, controller=c_id)


def get_controllers_access(username):
    u_id = "users/" + username
    aql = ('FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess '
             'LET models = '
               '(FOR model, mEdge in 1..1 INBOUND @u_id modelAccess '
                    'FILTER model._key in c.models '
                    'RETURN {name: model.name, '
                            'access: mEdge.access}) '
           'RETURN {name: c.name, access: cEdge.access, models: models, type: c.type}')
    controllers = execute_aql_query(aql, rawResults=True, u_id=u_id)
    # The variable 'controllers' is NOT a list but an iterator so we can not return that.
    # We have to iterate over 'controllers' and add every element to a list because
    # a list is JSON serializable and an iterator is not.
    results = []
    for c in controllers:
        results.append(c)
    return results


def add_user_to_controller(c_name, username, access):
    """Creates or updates an Edge (relation) between a controller and a user."""
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ("UPSERT { _from: @controller, _to: @user }"
           "INSERT { _from: @controller, _to: @user, access: @access}"
           "UPDATE { access : @access } in controllerAccess")
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
    """Removes the controller from the collection 'controllers'."""
    aql = 'REMOVE {_key: @controller} IN controllers'
    execute_aql_query(aql, controller=c_name)


def remove_edges_controller_access(c_name):
    """Removes all Edges from the collection 'controllerAccess' that contain
    the given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR edge in controllerAccess '
           'FILTER edge._from == @controller '
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, controller=c_id)


def add_model_to_controller(c_name, m_key):
    c_id = "controllers/" + c_name
    aql = ('LET doc = DOCUMENT(@controller) '
           'UPDATE doc WITH {'
           'models: PUSH(doc.models, @model, true)'
           '} IN controllers')
    execute_aql_query(aql, controller=c_id, model=m_key)


def get_controller_access(c_name, username):
    """Returns the access level that a user has to a controller."""
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR controller, cEdge IN 1..1 INBOUND @u_id controllerAccess  '
               'FILTER cEdge._from == @c_id '
               'RETURN cEdge.access ')
    return execute_aql_query(aql, rawResults=True, c_id=c_id, u_id=u_id)[0]


def get_controller_and_access(c_name, username):
    """Returns info about the controller AND the access level of the given user
    in one dictionary."""
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR controller, cEdge IN 1..1 INBOUND @u_id controllerAccess  '
               'FILTER cEdge._from == @c_id '
               'LET models = '
                 '(FOR model, mEdge in 1..1 INBOUND @u_id modelAccess '
                      'FILTER model._key in controller.models '
                      'RETURN {name: model.name, '
                              'access: mEdge.access}) '
               'RETURN {access: cEdge.access, name: controller.name, '
                       'models: models, type: controller.type}')
    return execute_aql_query(aql, rawResults=True, c_id=c_id, u_id=u_id)[0]


def set_controller_access(c_name, username, access):
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ("UPSERT { _from: @c_id, _to: @u_id }"
           "INSERT { _from: @c_id, _to: @u_id, access: @access}"
           "UPDATE { access : @access } in controllerAccess")
    execute_aql_query(aql, c_id=c_id, u_id=u_id, access=access)


def get_keys_controllers():
    aql = 'FOR c in controllers RETURN c._key'
    return execute_aql_query(aql, rawResults=True)


################################################################################
#                               MODEL FUNCTIONS                                #
################################################################################


def create_model(m_name, state, uuid):
    #create_models_collection()
    # TODO: Check if model with that name already exists. In this layer?
    model = {
        "name": m_name,
        "state": state,
        "uuid": uuid}
    aql = "INSERT @model INTO models LET newModel = NEW RETURN newModel"
    return execute_aql_query(aql, rawResults=True, model=model)[0]


def get_model(m_key):
    m_id = "models/" + m_key
    aql = 'RETURN DOCUMENT(@m_id)'
    return  execute_aql_query(aql, rawResults=True, m_id=m_id)[0]


def get_all_models(c_name):
    c_id = "controllers/" + c_name
    aql = ('LET c = DOCUMENT(@controller) '
           'FOR m_key in c.models '
                'LET m = DOCUMENT(CONCAT("models/",m_key)) '
                'RETURN m')
    return execute_aql_query(aql, rawResults=True, controller=c_id)


def delete_model(c_name, m_key):
    remove_model_m_col(m_key)
    remove_edges_models_access(m_key)
    remove_model_from_controller(c_name, m_key)


def remove_model_m_col(m_key):
    """Removes the model from the collection 'models'."""
    aql = 'REMOVE {_key: @model} IN models'
    execute_aql_query(aql, model=m_key)


def remove_edges_models_access(m_key):
    """Removes all Edges from the collection 'modelAccess' that contain
    the given model."""
    m_id = "models/" + m_key
    aql = ('FOR edge in modelAccess '
           'FILTER edge._from == @model '
           'REMOVE edge in modelAccess')
    execute_aql_query(aql, model=m_id)


def remove_model_from_controller(c_name, m_key):
    c_id = "controllers/" + c_name
    aql = ('LET doc = DOCUMENT(@controller)'
           'UPDATE doc WITH {'
           'models: REMOVE_VALUE(doc.models, @model)'
           '} IN controllers)')
    execute_aql_query(aql, controller=c_id, model=m_key)


def set_model_state(m_key, state, credential=None, uuid=None):
    # TODO: Erg dat bij error de None values worden gebruikt?
    # TODO: Methode opsplitsen in 3? 1 methode per veld.
    aql = ('UPDATE @model WITH {'
           'state: @state, '
           'credential: @credential, '
           'uuid: @uuid'
           '} IN models')
    execute_aql_query(aql, model=m_key, state=state, credential=credential, uuid=uuid)


def check_model_state(m_name):
    # TODO: To test
    aql = ('FOR m IN models '
           'FILTER m._key == @model '
           'RETURN m.state')
    return execute_aql_query(aql, rawResults=True, model=m_name)[0]


def get_model_access(c_name, m_name, username):
    #TODO: CHECK
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('LET c = DOCUMENT(@controller) '
           'FOR model, mEdge in 1..1 INBOUND @user modelAccess '
                'FILTER model._key in c.models '
                'FILTER model.name == @model '
                'RETURN mEdge.access ')
    result = execute_aql_query(aql, rawResults=True, controller=c_id, model=m_name, user=u_id)
    if bool(result):
        return result[0]


def get_models_access(c_name, username):
    u_id = "users/" + username
    c_id = "controllers/" + c_name
    aql = ('LET c = DOCUMENT(@controller) '
           'LET models = '
                '(FOR model, mEdge in 1..1 INBOUND @user modelAccess '
                    'FILTER model._key in c.models '
                    'RETURN {name: model.name, access: mEdge.access}) '
            'RETURN models')
    return execute_aql_query(aql, rawResults=True, controller=c_id, user=u_id)[0]


def set_model_access(m_key, username, access):
    # TODO: Aanpassen in andere files.
    # TODO: Gaat er van uit dat er al access edge is. UPSERT gebruiken?
    # TODO: Testen.
    m_id = "models/" + m_key
    u_id = "users/" + username
    aql = ("UPSERT { _from: @model, _to: @user }"
           "INSERT { _from: @model, _to: @user, access: @access}"
           "UPDATE { access : @access } in modelAccess")
    execute_aql_query(aql, model=m_id, user=u_id, access=access)


def get_model_key(c_name, m_name):
    controller = get_controller(c_name)
    key = find_model_key(controller["models"], m_name)
    return key


def find_model_key(model_keys, m_name):
    # TODO: Rename function
    for key in model_keys:
        model = get_model(key)
        if model["name"] == m_name:
            return key
    return None


def get_users_model(m_key):
    m_id = "models/" + m_key
    aql = ('FOR edge in modelAccess '
           'FILTER edge._from == @model '
           'LET u = '
           '(FOR u in users FILTER u._id == edge._to RETURN u) '
           'RETURN MERGE(u)')
    return execute_aql_query(aql, model=m_id)
