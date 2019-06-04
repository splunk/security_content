"""
`ca_certs_locater` is a lib for extending httplib2 to allow system certificate store to be used when
verifying SSL certificates, to enable this lib, you should add it to your python import path before
initializing httplib2. As we're not trying to implement SSL certificate RFCs, parsing and validating
certificates are not included.
"""

import atexit
import os
import os.path as op
import ssl
import sys

TEMP_CERT_FILE_NAME = 'httplib2_merged_certificates_{}.crt'
LINUX_CERT_PATH_1 = '/etc/pki/tls/certs/ca-bundle.crt'  # RedHat
LINUX_CERT_PATH_2 = '/etc/ssl/certs/ca-certificates.crt'  # Debian
DARWIN_CERT_PATH = '/usr/local/etc/openssl/cert.pem'
HTTPLIB2_CA_CERT_FILE_NAME = 'cacerts.txt'

TEMP_CERT_FILE_PATH = None


def get():
    """
    Returns: a path to generated certificate authority file

    """
    try:
        return _get()
    except (IOError, OSError, ssl.SSLError):
        _fallback()  # IO and SSL relative errors should be swallowed to protect the HTTP request


def _get():
    global TEMP_CERT_FILE_PATH
    # also check file existence as it's possible for the temp file to be deleted
    if TEMP_CERT_FILE_PATH is None or not os.path.exists(TEMP_CERT_FILE_PATH):
        temp_cert_file_path = _generate_temp_cert_file_name()
        ssl_ca_certs = _read_ssl_default_ca_certs()
        if not ssl_ca_certs:
            # it's possible the ca load path is not well configured, try some typical paths
            ssl_ca_certs = _read_platform_pem_cert_file()

        if ssl_ca_certs:  # only update temp cert file when there's additional PEM certs found
            cert_files = [ssl_ca_certs, _read_httplib2_default_certs()]
            _update_temp_cert_file(temp_cert_file_path, cert_files)
            TEMP_CERT_FILE_PATH = temp_cert_file_path
        else:
            _fallback()

    return TEMP_CERT_FILE_PATH


def _fallback():
    """
        Give up the loading process by throwing specified exception, httplib2 will then use its
        bundled certificates
    """
    raise ImportError('Unable to load system certificate authority files')


def _read_platform_pem_cert_file():
    if sys.platform.startswith('linux'):
        pem_files = [_read_pem_file(LINUX_CERT_PATH_1), _read_pem_file(LINUX_CERT_PATH_2)]
        return '\n'.join(filter(None, pem_files))
    elif sys.platform.startswith('darwin'):
        return _read_pem_file(DARWIN_CERT_PATH)
    else:
        return ""


def _read_ssl_default_ca_certs():
    # it's not guaranteed to return PEM formatted certs when `binary_form` is False
    der_certs = ssl.create_default_context().get_ca_certs(binary_form=True)
    pem_certs = [ssl.DER_cert_to_PEM_cert(der_cert_bytes) for der_cert_bytes in der_certs]
    return '\n'.join(pem_certs)


def _read_httplib2_default_certs():
    import httplib2  # import error should not happen here, and will be well handled by outer called
    httplib_dir = os.path.dirname(os.path.abspath(httplib2.__file__))
    ca_certs_path = os.path.join(httplib_dir, HTTPLIB2_CA_CERT_FILE_NAME)
    return _read_pem_file(ca_certs_path)


def _read_pem_file(path):
    if os.path.exists(path):
        with open(path, mode='r') as pem_file:
            return pem_file.read()
    else:
        return ""


def _update_temp_cert_file(temp_file, pem_texts):
    with open(temp_file, mode='w') as temp_cert_file:
        for pem_text in pem_texts:
            if len(pem_text) > 0:
                temp_cert_file.write(pem_text + '\n')
        temp_cert_file.flush()
    atexit.register(_do_safe_remove, temp_file)


def _do_safe_remove(file_path):
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except:
            pass


def _get_temp_cert_file_dir():
    import __main__
    app_root = op.dirname(op.dirname(op.abspath(__main__.__file__)))

    temp_dir = op.join(app_root, 'temp_certs')
    if not op.isdir(temp_dir):
        try:
            os.mkdir(temp_dir)
        except:
            pass
    for candidate in ['temp_certs', 'local', 'default']:
        dir_path = op.join(app_root, candidate)
        if op.isdir(dir_path):
            return dir_path
    return app_root


def _generate_temp_cert_file_name():
    file_name = TEMP_CERT_FILE_NAME.format(os.getpid())
    return os.path.join(_get_temp_cert_file_dir(), file_name)
