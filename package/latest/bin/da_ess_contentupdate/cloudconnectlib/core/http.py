import time
import traceback

from httplib2 import ProxyInfo, Http, socks, SSLHandshakeError
from solnlib.packages.requests import PreparedRequest, utils
from . import defaults
from .exceptions import HTTPError
from ..common.log import get_cc_logger

_logger = get_cc_logger()


class HTTPResponse(object):
    """
    HTTPResponse class wraps response of HTTP request for later use.
    """

    def __init__(self, response, content):
        """Construct a HTTPResponse from response and content returned
        with httplib2 request"""
        self._status_code = response.status
        self._header = response
        self._body = self._decode_content(response, content)

    @staticmethod
    def _decode_content(response, content):
        if not content:
            return ''

        charset = utils.get_encoding_from_headers(response)

        if charset is None:
            charset = defaults.charset
            _logger.info(
                'Unable to find charset in response headers,'
                ' set it to default "%s"', charset
            )

        _logger.info('Decoding response content with charset=%s', charset)

        try:
            return content.decode(charset, errors='replace')
        except Exception as ex:
            _logger.warning(
                'Failure decoding response content with charset=%s,'
                ' decode it with utf-8: %s',
                charset, ex.message
            )

        return content.decode('utf-8', errors='replace')

    @property
    def header(self):
        return self._header

    @property
    def body(self):
        """
        Return response body as a `string`.
        :return: A `string`
        """
        return self._body

    @property
    def status_code(self):
        """
        Return response status code.
        :return: A `integer`
        """
        return self._status_code


def _make_prepare_url_func():
    """Expose prepare_url in `PreparedRequest`"""
    pr = PreparedRequest()

    def prepare_url(url, params=None):
        """Prepare the given HTTP URL with ability provided in requests lib.
        For some illegal characters in URL or parameters like space(' ') will
        be escaped to make sure we can request the correct URL."""
        pr.prepare_url(url, params=params)
        return pr.url

    return prepare_url


class HTTPRequest(object):
    """
    HTTPRequest class represents a single request to send HTTP request until
    reached it's stop condition.
    """

    _PROXY_TYPE = {
        'http': socks.PROXY_TYPE_HTTP,
        'http_no_tunnel': socks.PROXY_TYPE_HTTP_NO_TUNNEL,
        'socks4': socks.PROXY_TYPE_SOCKS4,
        'socks5': socks.PROXY_TYPE_SOCKS5,
    }

    def __init__(self, proxy=None):
        """Constructs a `HTTPRequest` with a optional proxy setting.
        :param proxy: A optional `Proxy` object contains proxy related
         settings.
        """
        self._proxy_info = self._prepare_proxy_info(proxy)
        self._connection = None
        self._prepare_url_func = _make_prepare_url_func()

    def _send_request(self, uri, method, headers=None, body=None):
        """Do send request to target URL and validate SSL cert by default.
        If validation failed, disable it and try again."""
        if self._connection is None:
            self._connection = self._build_http_connection(
                proxy_info=self._proxy_info,
                disable_ssl_cert_validation=False)

        try:
            return self._connection.request(
                uri, body=body, method=method, headers=headers
            )
        except SSLHandshakeError:
            _logger.warning(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verification failed. "
                "The certificate of the https server [%s] is not trusted, "
                "this add-on will proceed to connect with this certificate. "
                "You may need to check the certificate and "
                "refer to the documentation and add it to the trust list. %s",
                uri,
                traceback.format_exc()
            )

            self._connection = self._build_http_connection(
                proxy_info=self._proxy_info,
                disable_ssl_cert_validation=True
            )
            return self._connection.request(
                uri, body=body, method=method, headers=headers
            )

    def request(self, url, method='GET', headers=None, body=None):
        """
        Invoke a request with httplib2 and return it's response.
        :param url: url address to send request to.
        :param method: request method `GET` by default.
        :param headers: request headers.
        :param body: request body.
        :return: A `HTTPResponse` object.
        """

        if body and not isinstance(body, str):
            raise TypeError('Request body type must be str')

        if self._connection is None:
            self._connection = self._build_http_connection(self._proxy_info)

        try:
            uri = self._prepare_url_func(url)
        except Exception:
            _logger.warning(
                'Failed to encode url=%s: %s, use original url directly',
                url, traceback.format_exc()
            )
            uri = url

        _logger.info('Preparing to invoke request to [%s]', uri)

        result = self._do_request(uri, method, headers, body)

        _logger.info('Invoking request to [%s] finished', uri)

        return result

    def _prepare_proxy_info(self, proxy):
        if not proxy or not proxy.enabled:
            _logger.debug('Proxy is not enabled')
            return None

        username = proxy.username \
            if 'username' in proxy and proxy.username else None
        password = proxy.password \
            if 'password' in proxy and proxy.password else None

        proxy_type = self._PROXY_TYPE.get(proxy.type) or self._PROXY_TYPE['http']

        return ProxyInfo(proxy_host=proxy.host,
                         proxy_port=int(proxy.port),
                         proxy_type=proxy_type,
                         proxy_user=username,
                         proxy_pass=password,
                         proxy_rdns=proxy.rdns)

    @staticmethod
    def _build_http_connection(
            proxy_info=None,
            timeout=defaults.timeout,
            disable_ssl_cert_validation=defaults.disable_ssl_cert_validation):
        return Http(
            proxy_info=proxy_info,
            timeout=timeout,
            disable_ssl_certificate_validation=disable_ssl_cert_validation)

    @staticmethod
    def _is_need_retry(status, retried, maximum_retries):
        return retried < maximum_retries \
               and status in defaults.retry_statuses

    def _do_request(self, uri, method='GET', headers=None, body=None):
        """Invokes request and auto retry with an exponential backoff
        if the response status is configured in defaults.retry_statuses."""
        retries = max(defaults.retries, 0)

        for i in xrange(retries + 1):
            try:
                response, content = self._send_request(
                    uri, body=body, method=method, headers=headers
                )
            except Exception as err:
                _logger.exception(
                    'Could not send request url=%s method=%s', uri, method)
                raise HTTPError('HTTP Error %s' % str(err))

            status = response.status

            if self._is_need_retry(status, i, retries):
                delay = 2 ** i
                _logger.warning(
                    'The response status=%s of request which url=%s and'
                    ' method=%s. Retry after %s seconds.',
                    status, uri, method, delay,
                )
                time.sleep(delay)
                continue

            return HTTPResponse(response, content)
