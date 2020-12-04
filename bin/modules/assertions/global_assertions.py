# Do not remove these imports that appear unused.
# Functions in this modules are discovered by the assertion_parser through `getattr`

from modules.assertions.application.assertions import *
from modules.assertions.cloud.assertions import *
from modules.assertions.endpoint.assertions import *
from modules.assertions.network.assertions import *
from modules.assertions.web.assertions import *


def count_eq(n, output=[]):
    return len(output) == n


def count_lt(n, output=[]):
    return len(output) < n


def count_gt(n, output=[]):
    return len(output) > n


def count_lte(n, output=[]):
    return count_eq(n, output) or count_lt(n, output)


def count_gte(n, output=[]):
    return count_eq(n, output) or count_gt(n, output)


def count_not(n, output=[]):
    return count_lt(n, output) or count_gt(n, output)
