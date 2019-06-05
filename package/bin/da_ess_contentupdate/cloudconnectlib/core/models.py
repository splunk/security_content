import base64
import traceback

from .ext import lookup_method
from .template import compile_template
from ..common.log import get_cc_logger

_logger = get_cc_logger()


class _Token(object):
    """Token class wraps a template expression"""

    def __init__(self, source):
        """Constructs _Token from source. A rendered template
        will be created if source is string type because Jinja
        template must be a string."""
        self._source = source
        self._value_for = compile_template(source) \
            if isinstance(source, basestring) else None

    def render(self, variables):
        """Render value with variables if source is a string.
        Otherwise return source directly."""
        if self._value_for is None:
            return self._source
        try:
            return self._value_for(variables)
        except Exception as ex:
            _logger.warning(
                'Unable to render template "%s". Please make sure template is'
                ' a valid Jinja2 template and token is exist in variables. '
                'message=%s cause=%s',
                self._source,
                ex.message,
                traceback.format_exc()
            )
        return self._source


class DictToken(object):
    """DictToken wraps a dict which value is template expression"""

    def __init__(self, template_expr):
        self._tokens = {k: _Token(v)
                        for k, v in (template_expr or {}).iteritems()}

    def render(self, variables):
        return {k: v.render(variables) for k, v in self._tokens.iteritems()}


class BaseAuth(object):
    """A base class for all authorization classes"""

    def __call__(self, headers, context):
        raise NotImplementedError('Auth must be callable.')


class BasicAuthorization(BaseAuth):
    """BasicAuthorization class implements basic auth"""

    def __init__(self, options):
        if not options:
            raise ValueError('Options for basic auth unexpected to be empty')

        username = options.get('username')
        if not username:
            raise ValueError('Username is mandatory for basic auth')
        password = options.get('password')
        if not password:
            raise ValueError('Password is mandatory for basic auth')

        self._username = _Token(username)
        self._password = _Token(password)

    def __call__(self, headers, context):
        username = self._username.render(context)
        password = self._password.render(context)
        headers['Authorization'] = 'Basic %s' % base64.encodestring(
            username + ':' + password
        ).strip()


class Request(object):
    def __init__(self, url, method, header=None, auth=None, body=None):
        self._header = DictToken(header)
        self._url = _Token(url)
        self._method = method.upper()
        self._auth = auth
        self._body = DictToken(body)

    @property
    def header(self):
        return self._header

    @property
    def url(self):
        return self._url

    @property
    def method(self):
        return self._method

    @property
    def auth(self):
        return self._auth

    @property
    def body(self):
        return self._body

    def normalize_url(self, context):
        """Normalize url"""
        return self._url.render(context)

    def normalize_header(self, context):
        """Normalize headers which must be a dict which keys and values are
        string."""
        header = self.header.render(context)
        return {k: str(v) for k, v in header.iteritems()}

    def normalize_body(self, context):
        """Normalize body"""
        return self.body.render(context)


class _Function(object):
    def __init__(self, inputs, function):
        self._inputs = tuple(_Token(expr) for expr in inputs or [])
        self._function = function

    @property
    def inputs(self):
        return self._inputs

    def inputs_values(self, context):
        """
        Get rendered input values.
        """
        for arg in self._inputs:
            yield arg.render(context)

    @property
    def function(self):
        return self._function


class Task(_Function):
    """Task class wraps a task in processor pipeline"""

    def __init__(self, inputs, function, output=None):
        super(Task, self).__init__(inputs, function)
        self._output = output

    @property
    def output(self):
        return self._output

    def execute(self, context):
        """Execute task with arguments which rendered from context """
        args = [arg for arg in self.inputs_values(context)]
        caller = lookup_method(self.function)
        output = self._output

        _logger.info(
            'Executing task method: [%s], input size: [%s], output: [%s]',
            self.function, len(args), output
        )

        if output is None:
            caller(*args)
            return {}

        return {output: caller(*args)}


class Condition(_Function):
    """A condition return the value calculated from input and function"""

    def calculate(self, context):
        """Calculate condition with input arguments rendered from context
        and method which expected return a bool result.
        :param context: context contains key value pairs
        :return A bool value returned from the corresponding method
        """
        args = [arg for arg in self.inputs_values(context)]
        callable_method = lookup_method(self.function)

        _logger.debug(
            'Calculating condition with method: [%s], input size: [%s]',
            self.function, len(args)
        )

        result = callable_method(*args)

        _logger.debug("Calculated result: %s", result)

        return result


class _Conditional(object):
    """A base class for all conditional action"""

    def __init__(self, conditions):
        self._conditions = conditions or []

    @property
    def conditions(self):
        return self._conditions

    def passed(self, context):
        """Determine if any condition is satisfied.
        :param context: variables to render template
        :return: `True` if all passed else `False`
        """
        return any(
            condition.calculate(context) for condition in self._conditions
        )


class Processor(_Conditional):
    """Processor class contains a conditional data process pipeline"""

    def __init__(self, skip_conditions, pipeline):
        super(Processor, self).__init__(skip_conditions)
        self._pipeline = pipeline or []

    @property
    def pipeline(self):
        return self._pipeline

    def should_skipped(self, context):
        """Determine processor if should skip process"""
        return self.passed(context)


class IterationMode(_Conditional):
    def __init__(self, iteration_count, conditions):
        super(IterationMode, self).__init__(conditions)
        self._iteration_count = iteration_count

    @property
    def iteration_count(self):
        return self._iteration_count

    @property
    def conditions(self):
        return self._conditions


class Checkpoint(object):
    """A checkpoint includes a namespace to determine the checkpoint location
    and a content defined the format of content stored in checkpoint."""

    def __init__(self, namespace, content):
        """Constructs checkpoint with given namespace and content template. """
        if not content:
            raise ValueError('Checkpoint content must not be empty')

        self._namespace = tuple(_Token(expr) for expr in namespace or ())
        self._content = DictToken(content)

    @property
    def namespace(self):
        return self._namespace

    def normalize_namespace(self, ctx):
        """Normalize namespace with context used to render template."""
        return [token.render(ctx) for token in self._namespace]

    @property
    def content(self):
        return self._content

    def normalize_content(self, ctx):
        """Normalize checkpoint with context used to render template."""
        return self._content.render(ctx)
