"""
SOC Query Language (SQL-injection safe) -> parameterized SQLite WHERE clause.

Grammar
-------
    query      := [expr] ( '|' command )*
    expr       := and_expr ( OR and_expr )*
    and_expr   := not_expr ( [AND] not_expr )*          -- whitespace = implicit AND
    not_expr   := ( NOT | '!' ) not_expr | atom
    atom       := '(' expr ')' | comparison | term
    comparison := FIELD op value
                | FIELD [NOT] IN '(' value (',' value)* ')'
                | FIELD ( CONTAINS | STARTSWITH | ENDSWITH ) value
                | FIELD EXISTS
    op         := '=' | '!=' | '>' | '>=' | '<' | '<='
    term       := WORD | STRING                          -- full-text search on raw_log
    command    := sort FIELD [asc|desc] | head N | limit N

Values may be "double quoted", 'single quoted' or bare words. '*' inside a value used with
'=' / '!=' is a wildcard.  All string matches are case-insensitive.

Examples
--------
    source_address="172.16.20.69" AND type=OS
    powershell AND NOT destination_address=172.16.20.69
    destination_port IN (80, 443) | sort timestamp asc | head 50
    process=*EDR-Freeze* OR raw_log CONTAINS "WerFaultSecure"
"""
from __future__ import annotations

from dataclasses import dataclass, field

# public field name -> (sql column, kind)
FIELDS: dict[str, tuple[str, str]] = {
    "timestamp": ("timestamp", "time"),
    "type": ("type", "str"),
    "source_address": ("source_address", "str"),
    "source_port": ("source_port", "int"),
    "destination_address": ("destination_address", "str"),
    "destination_port": ("destination_port", "int"),
    "hostname": ("hostname", "str"),
    "username": ("username", "str"),
    "process": ("process", "str"),
    "command_line": ("command_line", "str"),
    "action": ("action", "str"),
    "raw_log": ("raw_log", "str"),
    "id": ("id", "int"),
}
ALIASES = {
    "time": "timestamp", "_time": "timestamp", "date": "timestamp",
    "src": "source_address", "src_ip": "source_address", "source_ip": "source_address", "sourceip": "source_address",
    "dst": "destination_address", "dst_ip": "destination_address", "dest_ip": "destination_address",
    "destination_ip": "destination_address", "destinationip": "destination_address",
    "sport": "source_port", "src_port": "source_port",
    "dport": "destination_port", "dst_port": "destination_port", "dest_port": "destination_port",
    "host": "hostname", "user": "username", "image": "process",
    "cmd": "command_line", "commandline": "command_line",
    "raw": "raw_log", "message": "raw_log", "msg": "raw_log",
}
KEYWORDS = {"AND", "OR", "NOT", "IN", "CONTAINS", "STARTSWITH", "ENDSWITH", "EXISTS"}
COMPARATORS = {"=", "!=", ">", ">=", "<", "<="}
MAX_QUERY_LEN = 4000
MAX_DEPTH = 50


class QueryError(ValueError):
    def __init__(self, message: str, pos: int | None = None):
        super().__init__(message)
        self.message = message
        self.pos = pos


@dataclass
class Token:
    kind: str      # WORD, STRING, OP, LPAREN, RPAREN, COMMA, PIPE, NOT_BANG, EOF
    value: str
    pos: int


@dataclass
class CompiledQuery:
    where: str = "1=1"
    params: list = field(default_factory=list)
    order_by: str = "timestamp DESC, id DESC"
    limit: int | None = None
    terms: list[str] = field(default_factory=list)   # free-text terms (for highlighting)


def resolve_field(name: str, pos: int) -> tuple[str, str, str]:
    key = name.lower()
    key = ALIASES.get(key, key)
    if key not in FIELDS:
        raise QueryError(f"Unknown field '{name}'. Available: {', '.join(sorted(FIELDS))}", pos)
    col, kind = FIELDS[key]
    return key, col, kind


# --------------------------------------------------------------------------- lexer
def tokenize(text: str) -> list[Token]:
    if len(text) > MAX_QUERY_LEN:
        raise QueryError(f"Query too long (max {MAX_QUERY_LEN} characters)", MAX_QUERY_LEN)
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c in "\"'":
            quote, start, i = c, i, i + 1
            buf = []
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    i += 1
                buf.append(text[i])
                i += 1
            if i >= n:
                raise QueryError("Unterminated string literal", start)
            i += 1
            tokens.append(Token("STRING", "".join(buf), start))
        elif c == "(":
            tokens.append(Token("LPAREN", c, i)); i += 1
        elif c == ")":
            tokens.append(Token("RPAREN", c, i)); i += 1
        elif c == ",":
            tokens.append(Token("COMMA", c, i)); i += 1
        elif c == "|":
            tokens.append(Token("PIPE", c, i)); i += 1
        elif text.startswith(("!=", ">=", "<="), i):
            tokens.append(Token("OP", text[i:i + 2], i)); i += 2
        elif c in "=<>":
            tokens.append(Token("OP", c, i)); i += 1
        elif c == "!":
            tokens.append(Token("NOT_BANG", c, i)); i += 1
        else:
            start = i
            while i < n and not text[i].isspace() and text[i] not in "()\",'|=<>!":
                i += 1
            # allow '!' inside words only if not followed by '=' (e.g. "hello!world")
            tokens.append(Token("WORD", text[start:i], start))
    tokens.append(Token("EOF", "", n))
    return tokens


# --------------------------------------------------------------------------- parser / compiler
def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class _Parser:
    def __init__(self, text: str):
        self.tokens = tokenize(text)
        self.i = 0
        self.params: list = []
        self.terms: list[str] = []
        self.depth = 0

    # -- token helpers
    @property
    def cur(self) -> Token:
        return self.tokens[self.i]

    def peek(self, k: int = 1) -> Token:
        return self.tokens[min(self.i + k, len(self.tokens) - 1)]

    def advance(self) -> Token:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def is_kw(self, tok: Token, kw: str) -> bool:
        return tok.kind == "WORD" and tok.value.upper() == kw

    def expect(self, kind: str, what: str) -> Token:
        if self.cur.kind != kind:
            got = self.cur.value or "end of query"
            raise QueryError(f"Expected {what} but found '{got}'", self.cur.pos)
        return self.advance()

    # -- grammar
    def parse(self) -> CompiledQuery:
        cq = CompiledQuery()
        if self.cur.kind not in ("EOF", "PIPE"):
            cq.where = self.expr()
        while self.cur.kind == "PIPE":
            self.advance()
            self.command(cq)
        if self.cur.kind != "EOF":
            raise QueryError(f"Unexpected '{self.cur.value}'", self.cur.pos)
        cq.params = self.params
        cq.terms = self.terms
        return cq

    def expr(self) -> str:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise QueryError("Query is nested too deeply", self.cur.pos)
        parts = [self.and_expr()]
        while self.is_kw(self.cur, "OR"):
            self.advance()
            parts.append(self.and_expr())
        self.depth -= 1
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def _starts_operand(self, tok: Token) -> bool:
        if tok.kind in ("LPAREN", "STRING", "NOT_BANG"):
            return True
        return tok.kind == "WORD" and tok.value.upper() not in ("OR",)

    def and_expr(self) -> str:
        parts = [self.not_expr()]
        while True:
            if self.is_kw(self.cur, "AND"):
                self.advance()
                parts.append(self.not_expr())
            elif self._starts_operand(self.cur):
                parts.append(self.not_expr())      # implicit AND
            else:
                break
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def not_expr(self) -> str:
        if self.cur.kind == "NOT_BANG" or self.is_kw(self.cur, "NOT"):
            self.advance()
            return f"NOT ({self.not_expr()})"
        return self.atom()

    def atom(self) -> str:
        tok = self.cur
        if tok.kind == "LPAREN":
            self.advance()
            inner = self.expr()
            self.expect("RPAREN", "')'")
            return inner
        if tok.kind == "WORD" and tok.value.upper() in KEYWORDS:
            raise QueryError(f"Unexpected keyword '{tok.value}'", tok.pos)
        if tok.kind == "WORD":
            nxt = self.peek()
            if nxt.kind == "OP" or (nxt.kind == "WORD" and nxt.value.upper() in
                                    ("IN", "CONTAINS", "STARTSWITH", "ENDSWITH", "EXISTS", "NOT")
                                    and self._is_field_op_follow(nxt)):
                return self.comparison()
        if tok.kind in ("WORD", "STRING"):
            self.advance()
            return self.free_text(tok)
        raise QueryError(f"Unexpected '{tok.value or 'end of query'}'", tok.pos)

    def _is_field_op_follow(self, nxt: Token) -> bool:
        # "field NOT IN (...)"  vs  "powershell NOT cmd" (implicit AND NOT)
        if nxt.value.upper() == "NOT":
            return self.is_kw(self.peek(2), "IN")
        return True

    def free_text(self, tok: Token) -> str:
        if not tok.value:
            raise QueryError("Empty search term", tok.pos)
        self.terms.append(tok.value)
        return self._like("raw_log", tok.value, contains=True)

    def _like(self, col: str, value: str, contains=False, prefix=False, suffix=False, wildcard=False) -> str:
        if wildcard:
            pattern = "%".join(_like_escape(p) for p in value.split("*"))
        else:
            pattern = _like_escape(value)
            if contains or suffix:
                pattern = "%" + pattern
            if contains or prefix:
                pattern = pattern + "%"
        self.params.append(pattern)
        return f"{col} LIKE ? ESCAPE '\\'"

    def value(self, kind: str, fld: str) -> str | int:
        tok = self.cur
        if tok.kind not in ("WORD", "STRING"):
            raise QueryError(f"Expected a value for '{fld}'", tok.pos)
        self.advance()
        if kind == "int":
            try:
                return int(tok.value)
            except ValueError:
                raise QueryError(f"Field '{fld}' expects a number, got '{tok.value}'", tok.pos) from None
        if kind == "time":
            return tok.value.replace("T", " ")
        return tok.value

    def comparison(self) -> str:
        ftok = self.advance()
        name, col, kind = resolve_field(ftok.value, ftok.pos)
        optok = self.cur

        if optok.kind == "OP":
            self.advance()
            op = optok.value
            vtok = self.cur
            val = self.value(kind, name)
            if op in ("=", "!="):
                if kind == "str":
                    if isinstance(val, str) and "*" in val:
                        sql = self._like(col, val, wildcard=True)
                    else:
                        self.params.append(val)
                        sql = f"{col} = ? COLLATE NOCASE"
                    return f"NOT (COALESCE({sql}, 0))" if op == "!=" else sql
                if kind == "time" and "*" in str(val):
                    sql = self._like(col, str(val), wildcard=True)
                    return f"NOT ({sql})" if op == "!=" else sql
                self.params.append(val)
                return f"{col} {op} ?" if op == "=" else f"({col} IS NULL OR {col} != ?)"
            if kind == "str" and name != "timestamp":
                raise QueryError(f"Operator '{op}' is only valid for numeric or time fields", vtok.pos)
            self.params.append(val)
            return f"{col} {op} ?"

        kw = optok.value.upper()
        negate = False
        if kw == "NOT":
            self.advance()
            negate = True
            kw = self.cur.value.upper()
        self.advance()
        if kw == "EXISTS":
            return f"({col} IS NOT NULL AND {col} != '')"
        if kw == "IN":
            self.expect("LPAREN", "'(' after IN")
            vals = [self.value(kind, name)]
            while self.cur.kind == "COMMA":
                self.advance()
                vals.append(self.value(kind, name))
            self.expect("RPAREN", "')' to close IN list")
            if len(vals) > 500:
                raise QueryError("IN list too long (max 500)", optok.pos)
            self.params.extend(vals)
            coll = " COLLATE NOCASE" if kind == "str" else ""
            sql = f"{col}{coll} IN ({', '.join('?' * len(vals))})"
            return f"NOT (COALESCE({sql}, 0))" if negate else sql
        val = str(self.value("str", name))
        if kw == "CONTAINS":
            return self._like(col, val, contains=True)
        if kw == "STARTSWITH":
            return self._like(col, val, prefix=True)
        if kw == "ENDSWITH":
            return self._like(col, val, suffix=True)
        raise QueryError(f"Unknown operator '{optok.value}'", optok.pos)

    def command(self, cq: CompiledQuery) -> None:
        tok = self.expect("WORD", "a command (sort, head, limit)")
        cmd = tok.value.lower()
        if cmd == "sort":
            ftok = self.expect("WORD", "a field name after sort")
            desc = False
            fname = ftok.value
            if fname.startswith("-"):
                desc, fname = True, fname[1:]
            _, col, _ = resolve_field(fname, ftok.pos)
            if self.cur.kind == "WORD" and self.cur.value.lower() in ("asc", "desc"):
                desc = self.advance().value.lower() == "desc"
            cq.order_by = f"{col} {'DESC' if desc else 'ASC'}, id {'DESC' if desc else 'ASC'}"
        elif cmd in ("head", "limit"):
            ntok = self.expect("WORD", "a number")
            try:
                n = int(ntok.value)
            except ValueError:
                raise QueryError(f"'{cmd}' expects a number", ntok.pos) from None
            if not 1 <= n <= 10000:
                raise QueryError("Limit must be between 1 and 10000", ntok.pos)
            cq.limit = n
        else:
            raise QueryError(f"Unknown command '{tok.value}'. Supported: sort, head, limit", tok.pos)


def compile_query(text: str | None) -> CompiledQuery:
    text = (text or "").strip()
    if not text:
        return CompiledQuery()
    return _Parser(text).parse()
