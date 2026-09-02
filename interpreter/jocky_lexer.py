# jocky_lexer.py — JOCKY Language Full Lexer
# Tokenises JOCKY source code per the language spec.
# Supports all keywords, operators, literals, and comments.

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN TYPES
# ─────────────────────────────────────────────────────────────────────────────

# All keyword strings
KEYWORDS = frozenset([
    'func', 'return', 'if', 'else', 'for', 'while', 'break', 'continue',
    'module', 'import', 'type', 'struct', 'interface', 'const', 'var',
    'true', 'false', 'nil', 'defer', 'go', 'as', 'in', 'match', 'using',
    'unsafe', 'inline', 'make', 'append', 'case', 'default', 'fallthrough',
    'chan', 'map',
])


@dataclass
class Token:
    type:  str
    value: str
    line:  int
    col:   int

    def __repr__(self):
        return f'Token({self.type}, {self.value!r}, {self.line}:{self.col})'


class LexerError(Exception):
    def __init__(self, msg, line=0, col=0):
        super().__init__(f"Lexer error at {line}:{col} — {msg}")
        self.line = line
        self.col  = col


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN SPECIFICATION  (order matters — longer patterns first)
# ─────────────────────────────────────────────────────────────────────────────

_TOKEN_SPEC = [
    # Comments
    ('COMMENT_ML',  r'/\*[\s\S]*?\*/'),          # /* ... */
    ('COMMENT_SL',  r'//[^\n]*'),                 # // ...
    ('COMMENT_SH',  r'#[^\n]*'),                  # # hash comment

    # Raw string (backtick)
    ('RAW_STRING',  r'`[^`]*`'),

    # String (double-quoted with escape sequences)
    ('STRING',      r'"(?:[^"\\]|\\.)*"'),

    # Float literals (must come before INT)
    ('FLOAT',       r'\d+\.\d+(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+'),

    # Integer literals
    ('HEX',         r'0[xX][0-9a-fA-F]+'),
    ('OCT',         r'0[oO][0-7]+'),
    ('BIN',         r'0[bB][01]+'),
    ('INT',         r'\d+'),

    # Short assignment :=
    ('SHORT_ASSIGN', r':='),

    # Multi-char operators (order matters)
    ('ELLIPSIS',    r'\.\.\.'),
    ('DOTDOT',      r'\.\.'),
    ('ARROW',       r'->'),
    ('SHL_ASSIGN',  r'<<='),
    ('SHR_ASSIGN',  r'>>='),
    ('AND_ASSIGN',  r'&='),
    ('OR_ASSIGN',   r'\|='),
    ('XOR_ASSIGN',  r'\^='),
    ('ADD_ASSIGN',  r'\+='),
    ('SUB_ASSIGN',  r'-='),
    ('MUL_ASSIGN',  r'\*='),
    ('DIV_ASSIGN',  r'/='),
    ('MOD_ASSIGN',  r'%='),
    ('SHL',         r'<<'),
    ('SHR',         r'>>'),
    ('LEQ',         r'<='),
    ('GEQ',         r'>='),
    ('EQ',          r'=='),
    ('NEQ',         r'!='),
    ('AND',         r'&&'),
    ('OR',          r'\|\|'),

    # Single-char operators and delimiters
    ('AT',          r'@'),
    ('ASSIGN',      r'='),
    ('LT',          r'<'),
    ('GT',          r'>'),
    ('DOT',         r'\.'),
    ('COMMA',       r','),
    ('SEMI',        r';'),
    ('COLON',       r':'),
    ('LPAREN',      r'\('),
    ('RPAREN',      r'\)'),
    ('LBRACKET',    r'\['),
    ('RBRACKET',    r'\]'),
    ('LBRACE',      r'\{'),
    ('RBRACE',      r'\}'),
    ('PLUS',        r'\+'),
    ('MINUS',       r'-'),
    ('STAR',        r'\*'),
    ('SLASH',       r'/'),
    ('PERCENT',     r'%'),
    ('AMP',         r'&'),
    ('PIPE',        r'\|'),
    ('CARET',       r'\^'),
    ('BANG',        r'!'),

    # Whitespace / newlines
    ('NEWLINE',     r'\n'),
    ('WHITESPACE',  r'[ \t\r]+'),

    # Identifiers / Keywords (must come last among word tokens)
    ('IDENT',       r'[a-zA-Z_][a-zA-Z0-9_]*'),
]

_MASTER_RE = re.compile(
    '|'.join(f'(?P<{name}>{pattern})' for name, pattern in _TOKEN_SPEC),
    re.DOTALL,
)


# ─────────────────────────────────────────────────────────────────────────────
# LEXER
# ─────────────────────────────────────────────────────────────────────────────

class JockyLexer:
    """
    Full lexer for the JOCKY programming language.

    Usage:
        lexer  = JockyLexer()
        tokens = lexer.tokenize(source_string)
    """

    def tokenize(self, source: str) -> List[Token]:
        tokens: List[Token] = []
        line = 1
        line_start = 0

        for mo in _MASTER_RE.finditer(source):
            kind  = mo.lastgroup
            value = mo.group()
            col   = mo.start() - line_start + 1

            # ── skip insignificant tokens ──────────────────────────────────
            if kind in ('COMMENT_ML', 'COMMENT_SL', 'COMMENT_SH', 'WHITESPACE'):
                # Still need to track newlines inside multi-line comments
                if kind == 'COMMENT_ML':
                    nl_count = value.count('\n')
                    line += nl_count
                    if nl_count:
                        line_start = mo.start() + value.rfind('\n') + 1
                continue

            if kind == 'NEWLINE':
                line += 1
                line_start = mo.end()
                # JOCKY uses ';' as statement terminator; newlines are skipped
                continue

            # ── string literals ────────────────────────────────────────────
            if kind == 'STRING':
                # Strip quotes, process escapes
                inner = value[1:-1]
                inner = self._process_escapes(inner, line, col)
                tokens.append(Token('STRING', inner, line, col))
                continue

            if kind == 'RAW_STRING':
                tokens.append(Token('STRING', value[1:-1], line, col))
                continue

            # ── numeric literals ───────────────────────────────────────────
            if kind == 'HEX':
                tokens.append(Token('INT', str(int(value, 16)), line, col))
                continue
            if kind == 'OCT':
                tokens.append(Token('INT', str(int(value, 8)), line, col))
                continue
            if kind == 'BIN':
                tokens.append(Token('INT', str(int(value, 2)), line, col))
                continue
            if kind == 'INT':
                tokens.append(Token('INT', value, line, col))
                continue
            if kind == 'FLOAT':
                tokens.append(Token('FLOAT', value, line, col))
                continue

            # ── identifiers / keywords ─────────────────────────────────────
            if kind == 'IDENT':
                tok_type = 'KEYWORD' if value in KEYWORDS else 'IDENT'
                tokens.append(Token(tok_type, value, line, col))
                continue

            # ── everything else (operators, punctuation) ───────────────────
            tokens.append(Token(kind, value, line, col))

        # Check for unmatched characters
        matched_end = 0
        for mo in _MASTER_RE.finditer(source):
            if mo.start() > matched_end:
                bad_ch = source[matched_end]
                raise LexerError(f"Unexpected character {bad_ch!r}", line, 0)
            matched_end = mo.end()
        if matched_end < len(source) and source[matched_end:].strip():
            raise LexerError(f"Unexpected character at end of source", line, 0)

        return tokens

    # ── escape sequence processor ──────────────────────────────────────────
    @staticmethod
    def _process_escapes(s: str, line: int, col: int) -> str:
        result = []
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                c = s[i + 1]
                if   c == 'n':  result.append('\n'); i += 2
                elif c == 't':  result.append('\t'); i += 2
                elif c == '"':  result.append('"');  i += 2
                elif c == '\\': result.append('\\'); i += 2
                elif c == 'r':  result.append('\r'); i += 2
                elif c == '0':  result.append('\0'); i += 2
                elif c == 'x' and i + 3 < len(s):
                    hex_val = s[i+2:i+4]
                    result.append(chr(int(hex_val, 16)))
                    i += 4
                elif c == 'u' and i + 5 < len(s):
                    uni_val = s[i+2:i+6]
                    result.append(chr(int(uni_val, 16)))
                    i += 6
                else:
                    result.append(s[i])
                    i += 1
            else:
                result.append(s[i])
                i += 1
        return ''.join(result)
