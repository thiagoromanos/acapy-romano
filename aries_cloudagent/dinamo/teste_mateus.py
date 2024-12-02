from . import bindings
hSession = bindings.do_connection(HOST_ADDR="10.202.40.16", USER_ID="amateus", USER_PWD="Ghost1aa@123")
secret = bindings.create_shared_secret(hSession)