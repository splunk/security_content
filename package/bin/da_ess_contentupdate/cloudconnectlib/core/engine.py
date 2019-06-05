import json
import threading

from . import defaults
from .exceptions import HTTPError, StopCCEIteration
from .http import HTTPRequest
from ..common.log import get_cc_logger

_logger = get_cc_logger()


class CloudConnectEngine(object):
    """The cloud connect engine to process request instantiated
     from user options."""

    def __init__(self):
        self._stopped = False
        self._running_job = None

    @staticmethod
    def _set_logging(log_setting):
        _logger.set_level(log_setting.level)

    def start(self, context, config, checkpoint_mgr):
        """Start current client instance to execute each request parsed
         from config.
        """
        if not config:
            raise ValueError('Config must not be empty')

        context = context or {}
        global_setting = config.global_settings

        CloudConnectEngine._set_logging(global_setting.logging)

        _logger.info('Start to execute requests jobs.')
        processed = 0

        for request in config.requests:
            job = Job(
                request=request,
                context=context,
                checkpoint_mgr=checkpoint_mgr,
                proxy=global_setting.proxy,
            )
            self._running_job = job
            job.run()

            processed += 1
            _logger.info('%s job(s) process finished', processed)

            if self._stopped:
                _logger.info(
                    'Engine has been stopped, stopping to execute jobs.')
                break

        self._stopped = True
        _logger.info('Engine executing finished')

    def stop(self):
        """Stops engine and running job. Do nothing if engine already
        been stopped."""
        if self._stopped:
            _logger.info('Engine already stopped, do nothing.')
            return

        _logger.info('Stopping engine')

        if self._running_job:
            _logger.info('Attempting to stop the running job.')
            self._running_job.terminate()
            _logger.info('Stopping job finished.')

        self._stopped = True


class Job(object):
    """Job class represents a single request to send HTTP request until
    reached it's stop condition.
    """

    def __init__(self, request, context, checkpoint_mgr, proxy=None):
        """
        Constructs a `Job` with properties request, context and a
         optional proxy setting.
        :param request: A `Request` instance which contains request settings.
        :param context: A values set contains initial values for template
         variables.
        :param proxy: A optional `Proxy` object contains proxy related
         settings.
        """
        self._request = request
        self._context = context
        self._checkpoint_mgr = checkpoint_mgr
        self._client = HTTPRequest(proxy)
        self._stopped = True
        self._should_stop = False

        self._request_iterated_count = 0
        self._iteration_mode = self._request.iteration_mode
        self._max_iteration_count = self._get_max_iteration_count()

        self._running_thread = None
        self._terminated = threading.Event()

    def _get_max_iteration_count(self):
        mode_max_count = self._iteration_mode.iteration_count
        default_max_count = defaults.max_iteration_count
        return min(default_max_count, mode_max_count) \
            if mode_max_count > 0 else default_max_count

    def terminate(self, block=True, timeout=30):
        """Terminate this job, the current thread will blocked util
        the job is terminate finished if block is True """
        if self.is_stopped():
            _logger.info('Job already been stopped.')
            return

        if self._running_thread == threading.current_thread():
            _logger.warning('Job cannot terminate itself.')
            return

        _logger.info('Stopping job')
        self._should_stop = True

        if not block:
            return
        if not self._terminated.wait(timeout):
            _logger.warning('Terminating job timeout.')

    def _set_context(self, key, value):
        self._context[key] = value

    def _execute_tasks(self, tasks):
        if not tasks:
            return
        for task in tasks:
            if self._check_should_stop():
                return
            self._context.update(task.execute(self._context))

    def _on_pre_process(self):
        """
        Execute tasks in pre process one by one if condition satisfied.
        """
        pre_processor = self._request.pre_process

        if pre_processor.should_skipped(self._context):
            _logger.info('Skip pre process condition satisfied, do nothing')
            return

        tasks = pre_processor.pipeline
        _logger.debug(
            'Got %s tasks need be executed before process', len(tasks))
        self._execute_tasks(tasks)

    def _on_post_process(self):
        """
        Execute tasks in post process one by one if condition satisfied.
        """
        post_processor = self._request.post_process

        if post_processor.should_skipped(self._context):
            _logger.info('Skip post process condition satisfied, '
                         'do nothing')
            return

        tasks = post_processor.pipeline
        _logger.debug(
            'Got %s tasks need to be executed after process', len(tasks)
        )
        self._execute_tasks(tasks)

    def _update_checkpoint(self):
        """Updates checkpoint based on checkpoint namespace and content."""
        checkpoint = self._request.checkpoint
        if not checkpoint:
            _logger.info('Checkpoint not specified, do not update it.')
            return

        self._checkpoint_mgr.update_ckpt(
            checkpoint.normalize_content(self._context),
            namespaces=checkpoint.normalize_namespace(self._context),
        )

    def _get_checkpoint(self):
        checkpoint = self._request.checkpoint
        if not checkpoint:
            _logger.info('Checkpoint not specified, do not read it.')
            return

        namespaces = checkpoint.normalize_namespace(self._context)
        checkpoint = self._checkpoint_mgr.get_ckpt(namespaces)
        if checkpoint:
            self._context.update(checkpoint)

    def _is_stoppable(self):
        """Check if repeat mode conditions satisfied."""
        if self._request_iterated_count >= self._max_iteration_count:
            _logger.info(
                'Job iteration count is %s, current request count is %s,'
                ' stop condition satisfied.',
                self._max_iteration_count, self._request_iterated_count
            )
            return True

        if self._iteration_mode.passed(self._context):
            _logger.info('Job stop condition satisfied.')
            return True

        return False

    def is_stopped(self):
        """Return if this job is stopped."""
        return self._stopped

    def run(self):
        """Start job and exit util meet stop condition. """
        _logger.info('Start to process job')

        self._stopped = False
        try:
            self._running_thread = threading.current_thread()
            self._run()
        except Exception:
            _logger.exception('Error encountered while running job.')
            raise
        finally:
            self._terminated.set()
            self._stopped = True

        _logger.info('Job processing finished')

    def _check_should_stop(self):
        if self._should_stop:
            _logger.info('Job should been stopped.')
        return self._should_stop

    def _run(self):
        request = self._request.request
        method = request.method
        authorizer = request.auth
        self._get_checkpoint()

        while 1:
            if self._check_should_stop():
                return

            try:
                self._on_pre_process()
            except StopCCEIteration:
                _logger.info('Stop iteration command in pre process is received, exit job now.')
                return

            url = request.normalize_url(self._context)
            header = request.normalize_header(self._context)
            body = request.normalize_body(self._context)
            body_json = json.dumps(body) if body else None

            if authorizer:
                authorizer(header, self._context)

            if self._check_should_stop():
                return

            response, need_terminate = \
                self._send_request(url, method, header, body=body_json)

            if need_terminate:
                _logger.info('This job need to be terminated.')
                break

            self._request_iterated_count += 1
            self._set_context('__response__', response)
            if self._check_should_stop():
                return

            try:
                self._on_post_process()
            except StopCCEIteration:
                _logger.info('Stop iteration command in post process is received, exit job now.')
                return

            if self._check_should_stop():
                return
            self._update_checkpoint()

            if self._is_stoppable():
                _logger.info('Stop condition reached, exit job now')
                break

    def _send_request(self, url, method, header, body):
        """Do send request with a simple error handling strategy. Refer to
        https://confluence.splunk.com/display/PROD/CC+1.0+-+Detail+Design"""
        try:
            response = self._client.request(
                url, method, headers=header, body=body
            )
        except HTTPError as error:
            _logger.exception(
                'HTTPError reason=%s when sending request to '
                'url=%s method=%s', error.reason, url, method)
            return None, True

        status = response.status_code

        if status in defaults.success_statuses:
            if not (response.body or '').strip():
                _logger.info(
                    'The response body of request which url=%s and'
                    ' method=%s is empty, status=%s.',
                    url, method, status
                )
                return None, True
            return response, False

        error_log = ('The response status=%s for request which url=%s and'
                     ' method=%s.') % (
                        status, url, method
                    )

        if status in defaults.warning_statuses:
            _logger.warning(error_log)
        else:
            _logger.error(error_log)

        return None, True
