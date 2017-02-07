from charmhelpers.core import hookenv
from charms.reactive import hook
from charms.reactive import RelationBase
from charms.reactive import scopes


class SojoboProvides(RelationBase):
    scope = scopes.GLOBAL

    @hook('{provides:sojobo}-relation-{joined,changed}')
    def changed(self):
        self.set_state('{relation_name}.available')

    @hook('{provides:sojobo}-relation-{broken,departed}')
    def broken(self):
        self.remove_state('{relation_name}.available')

    def configure(self, port, api_key):
        relation_info = {
            'hostname': hookenv.unit_get('private-address'),
            'port': port,
            'api_key': api_key
        }
        self.set_remote(**relation_info)
