from sly import Lexer, Parser
import modules.assertions.global_assertions


class AssertionLexer(Lexer):
    tokens = {FUNC, NUMBER, STRING, AND, OR, XOR, NOT, LPAR, RPAR, ARG}
    ignore = ' \t'
    literals = {'&', '|', '^', '!', '(', ')'}

    @_(r'\((\s*("[^"]*"|\'[^\']*\'|\d+)\s*,?)+\)')
    def ARG(self, t):
        arguments = t.value[1:-1].split(",")
        args = []
        for a in arguments:
            a = a.strip()
            if a.isnumeric:
                args.append(float(a))
            else:
                args.append(a)
        t.value = args
        return t

    AND = r'\&'
    OR = r'\|'
    XOR = r'\^'
    NOT = r'\!'
    LPAR = r'\('
    RPAR = r'\)'
    FUNC = r'@[a-zA-Z0-9_]+'
    STRING = r'("[^"]*"|\'[^\']*\')'
    NUMBER = r'\d+'


class AssertionParser(Parser):
    tokens = AssertionLexer.tokens

    precedence = (
        ('left', AND, OR, XOR),
        ('right', NOT)
    )

    def __init__(self, events):
        self.names = {}
        self.events = events

    @_('FUNC ARG')
    def expr(self, p):
        f = getattr(modules.assertions.global_assertions, p.FUNC[1:])
        return f(output=self.events, *p.ARG)

    @_('FUNC LPAR RPAR')
    def expr(self, p):
        return "%s()" % p.FUNC

    @_('expr AND expr')
    def expr(self, p):
        return p.expr0 and p.expr1

    @_('expr OR expr')
    def expr(self, p):
        return p.expr0 or p.expr1

    @_('expr XOR expr')
    def expr(self, p):
        return p.expr0 != p.expr1

    @_('NOT expr')
    def expr(self, p):
        return not p.expr

    @_('LPAR expr RPAR')
    def expr(self, p):
        return p.expr

    @_('NUMBER')
    def expr(self, p):
        return int(p.NUMBER)

    @_('STRING')
    def expr(self, p):
        return p.STRING

    @_('ARG')
    def expr(self, p):
        return p.ARG


if __name__ == '__main__':
    lexer = AssertionLexer()
    parser = AssertionParser([1, 2, 3])

    code = "@count_gt(0) & (@count_lt(5))"
    for tok in lexer.tokenize(code):
        print('type=%r, value=%r' % (tok.type, tok.value))
    res = parser.parse(lexer.tokenize(code))
    print(res)
