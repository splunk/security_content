# encoding = utf-8

import logging
import sys

def get_stderr_stream_logger(logger_name=None, log_level=logging.INFO):
    if logger_name is None:
        logger_name = 'aob_default_logger'
    logger = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')
    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    stderr_handler.setLevel(logging.DEBUG)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)
    logger.setLevel(log_level)
    return logger
