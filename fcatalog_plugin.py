import idaapi
from idaapi import Form

import idautils
import idc
from fcatalog_client.ida_client import FCatalogClient,clean_idb

# Client configuration:
class ClientConfig(object):
    def __init__(self):
        self.db_name = None
        self.remote_host = None
        self.remote_port = None


##########################################################################

# Configuration stashing:

def save_sstring(s):
    """
    Save a short string inside the idb.
    """
    min_segment_addr = min(list(idautils.Segments()))
    # Keep the string as a regular comment on the first instruction:
    idc.MakeComm(min_segment_addr,s)


def load_sstring():
    """
    Load a short string from the idb.
    """
    min_segment_addr = min(list(idautils.Segments()))
    return idc.GetCommentEx(min_segment_addr,0)

def save_config(client_config):
    """
    Save configuration (client_config instance) to IDB.
    """
    config_str = "%%%"
    config_str += client_config.remote_host
    config_str += ":"
    config_str += str(client_config.remote_port)
    config_str += ":"
    config_str += client_config.db_name

    save_sstring(config_str)

def load_config():
    """
    Save configuration (client_config instance) to IDB.
    """
    config_str = load_sstring()
    if (config_str is None) or (not config_str.startswith('%%%')):
        return ClientConfig()

    # Skip the percents prefix:
    config_str = config_str[3:]

    remote_host,remote_port_str,db_name = config_str.split(':')
    remote_port = int(remote_port_str)

    # Create a client config instance and fill it with the loaded
    # configuration:
    client_config = ClientConfig()
    client_config.remote_host = remote_host
    client_config.remote_port = remote_port
    client_config.db_name = db_name

    return client_config



##########################################################################


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
        """
        Initialize plugin:
        """
        self._client_config = load_config()
        self._fcc = None
        if self._client_config is not None:
            self._fcc = FCatalogClient(\
                    (self._client_config.remote_host,\
                    self._client_config.remote_port),\
                    self._client_config.db_name)

        # Set up menus:
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
        """
        Terminate plugin
        """
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
        """
        Show the configuration form and update configuration values according
        to user choices.
        """
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
                save_config(self._client_config)
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

