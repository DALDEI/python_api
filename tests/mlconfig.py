import json
from marklogic.connection import Connection
from marklogic.auth import Auth
from unittest import TestCase

class MLConfig(TestCase):
    def __init__(self, *args, **kwargs):
        super(MLConfig,self).__init__(*args, **kwargs)

        config = { "hostname": "localhost", \
                   "username": "admin", \
                   "password": "admin", \
                   "protocol": "http", \
                   "management-port": 8002, \
                   "management-root": "/manage/v2", \
                   "client-port": 8000, \
                   "client-root": "/v1", \
                   "admin-port": 8001, \
                   "admin-root": "/admin/v1" }

        try:
            data_file = open("mlconfig.json").read()
            data = json.loads(data_file)
            for key in data:
                config[key] = data[key]
        except FileNotFoundError:
            pass

        self.auth = Auth(config["username"], config["password"])

        conn = Connection(config["hostname"], self.auth)

        conn.get_management_endpoint().set_port(config["management-port"])
        conn.get_management_endpoint().set_root(config["management-root"])
        conn.get_client_endpoint().set_port(config["client-port"])
        conn.get_client_endpoint().set_root(config["client-root"])
        conn.get_admin_endpoint().set_port(config["admin-port"])
        conn.get_admin_endpoint().set_root(config["admin-root"])

        self.connection = conn
