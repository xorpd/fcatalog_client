from idaapi import Form
from fcatalog_client.ida_client import FCatalogClient,clean_idb

# Client configuration:
class ClientConfig(object):
    def __init__(self):
        self.db_name = None
        self.remote_host = None
        self.remote_port = None


class ConfForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:host}
FCatalog Client Configuration
<#Host:{host}>
<#Port:{port}>
<#Database Name:{db_name}>
""", {
        'host': Form.StringInput(tp=Form.FT_TYPE),
        'port': Form.StringInput(tp=Form.FT_TYPE),
        'db_name': Form.StringInput(tp=Form.FT_TYPE),
    })



class FCatalogPlugin(idaapi.plugin_t):
    flags = 0
    comment = ''
    help = 'The Functions Catalog client'
    wanted_name = 'fcatalog_client'
    wanted_hotkey = ''

    def init(self):
        self._client_config = ClientConfig()
        self._fcc = None
        ui_path = "Edit/"
        self.menu_contexts = []

        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "FCatalog: Configure",
                                "",
                                0,
                                self._show_conf_form,
                                (None,)))

        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "FCatalog: Commit Functions",
                                "",
                                0,
                                self._commit_funcs,
                                (None,)))
        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "FCatalog: Find Similars",
                                "",
                                0,
                                self._find_similars,
                                (None,)))
        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "FCatalog: Clean IDB",
                                "",
                                0,
                                self._clean_idb,
                                (None,)))

        return idaapi.PLUGIN_KEEP

    def run(self,arg):
        pass

    def term(self):
        for context in self.menu_contexts:
            idaapi.del_menu_item(context)
        return None


    def _commit_funcs(self,arg):
        if self._fcc is None:
            print('Please configure FCatalog')
            return
        self._fcc.commit_funcs()

    def _find_similars(self,arg):
        if self._fcc is None:
            print('Please configure FCatalog')
            return
        self._fcc.find_similars()


    def _clean_idb(self,arg):
        """
        Clean the idb from fcatalog names or comments.
        """
        clean_idb()


    def _show_conf_form(self,arg):
        # Create form
        cf = ConfForm()

        # Compile (in order to populate the controls)
        cf.Compile()

        # Populate form fields with current configuration values:
        if self._client_config.remote_host is not None:
            cf.host.value = self._client_config.remote_host
        if self._client_config.remote_port is not None:
            cf.port.value = str(self._client_config.remote_port)
        if self._client_config.db_name is not None:
            cf.db_name.value = self._client_config.db_name

        # Execute the form
        res = cf.Execute()
        if res == 1:
            # User pressed OK:

            is_conf_good = True

            # Extract host:
            host = cf.host.value
            if len(host) == 0:
                host = None
                is_conf_good = False
            self._client_config.remote_host = host

            # Extract port:
            try:
                port = int(cf.port.value)
            except ValueError:
                port = None
                is_conf_good = False
            self._client_config.remote_port = port

            # Extract db name:
            db_name = cf.db_name.value
            if len(db_name) == 0:
                db_name = None
                is_conf_good = False
            self._client_config.db_name = db_name

            if is_conf_good:
                self._fcc = FCatalogClient(\
                        (self._client_config.remote_host,\
                        self._client_config.remote_port),\
                        self._client_config.db_name)
                print('Configuration successful.')
            else:
                print('Invalid configuration.')
                self._fcc = None


        # Dispose the form
        cf.Free()


def PLUGIN_ENTRY():
    return FCatalogPlugin()
