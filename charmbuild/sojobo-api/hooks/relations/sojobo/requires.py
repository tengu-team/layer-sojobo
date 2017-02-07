from charms.reactive import hook
from charms.reactive import RelationBase
from charms.reactive import scopes


class SojoboRequires(RelationBase):
    scope = scopes.UNIT

    @hook('{requires:sojobo}-relation-{joined,changed}')
    def changed(self):
        conv = self.conversation()
        if conv.get_remote('port') and conv.get_remote('api_key'):
            conv.set_state('{relation_name}.available')

    @hook('{requires:sojobo}-relation-{departed,broken}')
    def broken(self):
        conv = self.conversation()
        conv.remove_state('{relation_name}.available')

    def services(self):
        services = {}
        for conv in self.conversations():
            service_name = conv.scope.split('/')[0]
            service = services.setdefault(service_name, {
                'service_name': service_name,
                'hosts': [],
            })
            host = conv.get_remote('hostname')
            port = conv.get_remote('port')
            api_key = conv.get_remote('api_key')
            if host and port and api_key:
                service['hosts'].append({
                    'hostname': host,
                    'port': port,
                    'api_key': api_key
                })
        return [s for s in services.values() if s['hosts']]
