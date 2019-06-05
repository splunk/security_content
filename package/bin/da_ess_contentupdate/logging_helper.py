from solnlib.log import Logs


def get_logger(name):
    return Logs().get_logger(name)
