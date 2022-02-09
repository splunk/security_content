
def pytest_addoption(parser):
    parser.addoption("--token", action="store", default="scs token")
    parser.addoption("--env", action="store", default="scs environment")
    parser.addoption("--tenant", action="store", default="environment's tenant")

def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    option_value = metafunc.config.option.token
    if 'token' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("token", [option_value])
    env = metafunc.config.option.env
    if 'tenant' in metafunc.fixturenames and env is not None:
        metafunc.parametrize("env", [env])
    tenant = metafunc.config.option.tenant
    if 'tenant' in metafunc.fixturenames and tenant is not None:
        metafunc.parametrize("tenant", [tenant])
