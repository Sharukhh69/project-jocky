# jocky_parser.py — JOCKY Language Full Recursive-Descent Parser
# Consumes a token stream from JockyLexer and produces a typed AST.

from __future__ import annotations
from typing import List, Optional
from jocky_lexer import Token, LexerError
from jocky_ast import *


class ParseError(Exception):
    def __init__(self, msg: str, line: int = 0, col: int = 0):
        super().__init__(f"Parse error at {line}:{col} — {msg}")
        self.line = line
        self.col  = col


# ─────────────────────────────────────────────────────────────────────────────
# PARSER
# ─────────────────────────────────────────────────────────────────────────────

class JockyParser:
    """
    Recursive-descent parser for JOCKY.

    Usage:
        parser  = JockyParser(tokens)
        program = parser.parse()
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos    = 0

    # ── Token navigation ─────────────────────────────────────────────────────

    def peek(self, offset: int = 0) -> Optional[Token]:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)

    def check(self, *types_or_values) -> bool:
        """Returns True if current token matches any type or keyword value."""
        tok = self.peek()
        if tok is None:
            return False
        for tv in types_or_values:
            if tok.type == tv or tok.value == tv:
                return True
        return False

    def match(self, *types_or_values) -> Optional[Token]:
        """Consume and return current token if it matches, else None."""
        if self.check(*types_or_values):
            tok = self.tokens[self.pos]
            self.pos += 1
            return tok
        return None

    def expect(self, type_or_value: str, hint: str = "") -> Token:
        """Consume current token; raise ParseError if not matching."""
        tok = self.peek()
        if tok is None:
            raise ParseError(
                f"Expected {type_or_value!r} but reached end of file. {hint}",
                0, 0)
        if tok.type == type_or_value or tok.value == type_or_value:
            self.pos += 1
            return tok
        raise ParseError(
            f"Expected {type_or_value!r}, got {tok.value!r} ({tok.type}). {hint}",
            tok.line, tok.col)

    def consume(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def skip_semis(self):
        while self.match('SEMI'):
            pass

    # ── Top-level entry ───────────────────────────────────────────────────────

    def parse(self) -> Program:
        prog = Program(line=1, col=1)

        # Optional module declaration
        if self.check('module'):
            prog.module = self.parse_module_decl()
        self.skip_semis()

        # Collect top-level declarations
        while not self.at_end():
            self.skip_semis()
            if self.at_end():
                break

            tok = self.peek()
            if tok is None:
                break

            if tok.value == 'import':
                prog.imports.append(self.parse_import())
            elif tok.value == 'func':
                # Check for @attribute before func
                attrs = []
                prog.functions.append(self.parse_func_decl(attrs))
            elif tok.value == 'struct':
                prog.structs.append(self.parse_struct_decl())
            elif tok.value == 'interface':
                prog.interfaces.append(self.parse_interface_decl())
            elif tok.value == 'const':
                prog.globals.append(self.parse_const_decl())
            elif tok.value == 'var':
                prog.globals.append(self.parse_var_decl())
            elif tok.type == 'AT':
                # @attribute decorator before func
                attrs = self.parse_attributes()
                if self.check('func'):
                    prog.functions.append(self.parse_func_decl(attrs))
                else:
                    self.consume()  # skip
            else:
                # Bare statement at top level — wrap as entry point
                stmt = self.parse_statement()
                if stmt:
                    prog.globals.append(stmt)

        return prog

    # ── Module / Import ───────────────────────────────────────────────────────

    def parse_module_decl(self) -> ModuleDecl:
        tok = self.expect('module')
        name_tok = self.expect('IDENT')
        self.skip_semis()
        return ModuleDecl(name=name_tok.value, line=tok.line, col=tok.col)

    def parse_import(self) -> ImportDecl:
        tok = self.expect('import')
        path_tok = self.expect('STRING')
        alias = ""
        if self.check('as'):
            self.consume()
            alias = self.expect('IDENT').value
        self.skip_semis()
        return ImportDecl(path=path_tok.value, alias=alias,
                          line=tok.line, col=tok.col)

    # ── Attributes (@polymorphic, @encrypt, ...) ─────────────────────────────

    def parse_attributes(self) -> List[str]:
        attrs = []
        while self.match('AT'):
            name = self.expect('IDENT')
            attrs.append(name.value)
        return attrs

    # ── Type references ───────────────────────────────────────────────────────

    def parse_type(self) -> ASTNode:
        tok = self.peek()
        if tok is None:
            raise ParseError("Expected type", 0, 0)

        # Pointer: *T
        if self.match('STAR'):
            base = self.parse_type()
            return PointerTypeRef(base=base, line=tok.line, col=tok.col)

        # Array/slice: []T or [N]T
        if self.match('LBRACKET'):
            if self.check('RBRACKET'):
                self.expect('RBRACKET')
                elem = self.parse_type()
                return ArrayTypeRef(size=None, element=elem,
                                    line=tok.line, col=tok.col)
            else:
                size = self.parse_expression()
                self.expect('RBRACKET')
                elem = self.parse_type()
                return ArrayTypeRef(size=size, element=elem,
                                    line=tok.line, col=tok.col)

        # Map: map[K]V
        if self.check('map'):
            self.consume()
            self.expect('LBRACKET')
            key_type = self.parse_type()
            self.expect('RBRACKET')
            val_type = self.parse_type()
            return MapTypeRef(key=key_type, value=val_type,
                              line=tok.line, col=tok.col)

        # Chan: chan T
        if self.check('chan'):
            self.consume()
            elem = self.parse_type()
            return ChanTypeRef(element=elem, line=tok.line, col=tok.col)

        # Func type: func(Params) : RetType
        if self.check('func'):
            self.consume()
            params, returns = self.parse_signature_types()
            return FuncTypeRef(params=params, returns=returns,
                               line=tok.line, col=tok.col)

        # Named type (identifier)
        name_tok = self.expect('IDENT')
        return TypeRef(name=name_tok.value, line=name_tok.line, col=name_tok.col)

    def parse_signature_types(self):
        """Parse ( param_types ) : return_type — returns (params, returns)"""
        self.expect('LPAREN')
        param_types = []
        while not self.check('RPAREN') and not self.at_end():
            param_types.append(self.parse_type())
            if not self.match('COMMA'):
                break
        self.expect('RPAREN')
        returns = []
        if self.match('COLON'):
            returns.append(self.parse_type())
        return param_types, returns

    # ── Function declaration ──────────────────────────────────────────────────

    def parse_func_decl(self, attributes: List[str] = None) -> FuncDecl:
        tok = self.expect('func')
        name_tok = self.expect('IDENT')
        is_exported = name_tok.value[0].isupper()

        params, returns = self.parse_params_and_returns()
        body = self.parse_block()

        return FuncDecl(
            name=name_tok.value,
            params=params,
            returns=returns,
            body=body,
            attributes=attributes or [],
            is_exported=is_exported,
            line=tok.line, col=tok.col,
        )

    def parse_params_and_returns(self):
        """Parse (params) : RetType → (List[ParamDecl], List[TypeRef])"""
        self.expect('LPAREN')
        params = []
        while not self.check('RPAREN') and not self.at_end():
            param = self.parse_param()
            params.append(param)
            if not self.match('COMMA'):
                break
        self.expect('RPAREN')

        returns = []
        if self.match('COLON'):
            # Multiple returns: (T, T)
            if self.match('LPAREN'):
                while not self.check('RPAREN') and not self.at_end():
                    returns.append(self.parse_type())
                    if not self.match('COMMA'):
                        break
                self.expect('RPAREN')
            else:
                returns.append(self.parse_type())

        return params, returns

    def parse_param(self) -> ParamDecl:
        tok = self.peek()
        # variadic: ...Type or name ...Type
        variadic = False
        if self.match('ELLIPSIS'):
            variadic = True
            typ = self.parse_type()
            return ParamDecl(name='', type_ref=typ, variadic=True,
                             line=tok.line, col=tok.col)

        name_tok = self.expect('IDENT')
        type_ref = None
        if self.match('COLON'):
            type_ref = self.parse_type()
        elif self.match('ELLIPSIS'):
            variadic = True
            type_ref = self.parse_type()

        return ParamDecl(name=name_tok.value, type_ref=type_ref,
                         variadic=variadic, line=name_tok.line, col=name_tok.col)

    # ── Struct / Interface ────────────────────────────────────────────────────

    def parse_struct_decl(self) -> StructDecl:
        tok = self.expect('struct')
        name_tok = self.expect('IDENT')
        self.expect('LBRACE')
        fields = []
        while not self.check('RBRACE') and not self.at_end():
            self.skip_semis()
            if self.check('RBRACE'):
                break
            f_name = self.expect('IDENT')
            self.expect('COLON')
            f_type = self.parse_type()
            self.skip_semis()
            fields.append(FieldDecl(name=f_name.value, type_ref=f_type,
                                    line=f_name.line, col=f_name.col))
        self.expect('RBRACE')
        return StructDecl(name=name_tok.value, fields=fields,
                          line=tok.line, col=tok.col)

    def parse_interface_decl(self) -> InterfaceDecl:
        tok = self.expect('interface')
        name_tok = self.expect('IDENT')
        self.expect('LBRACE')
        methods = []
        while not self.check('RBRACE') and not self.at_end():
            self.skip_semis()
            if self.check('RBRACE'):
                break
            m_name = self.expect('IDENT')
            params, returns = self.parse_params_and_returns()
            self.skip_semis()
            methods.append(MethodSig(name=m_name.value, params=params,
                                     returns=returns, line=m_name.line))
        self.expect('RBRACE')
        return InterfaceDecl(name=name_tok.value, methods=methods,
                             line=tok.line, col=tok.col)

    # ── Variable / Constant declarations ─────────────────────────────────────

    def parse_var_decl(self) -> VarDecl:
        tok = self.expect('var')
        name_tok = self.expect('IDENT')
        type_ref = None
        value = None
        if self.match('COLON'):
            type_ref = self.parse_type()
        if self.match('ASSIGN'):
            value = self.parse_expression()
        self.skip_semis()
        return VarDecl(name=name_tok.value, type_ref=type_ref, value=value,
                       line=tok.line, col=tok.col)

    def parse_const_decl(self) -> ConstDecl:
        tok = self.expect('const')
        name_tok = self.expect('IDENT')
        type_ref = None
        if self.match('COLON'):
            type_ref = self.parse_type()
        self.expect('ASSIGN')
        value = self.parse_expression()
        self.skip_semis()
        return ConstDecl(name=name_tok.value, type_ref=type_ref, value=value,
                         line=tok.line, col=tok.col)

    # ── Block ─────────────────────────────────────────────────────────────────

    def parse_block(self) -> Block:
        tok = self.expect('LBRACE')
        stmts = []
        while not self.check('RBRACE') and not self.at_end():
            self.skip_semis()
            if self.check('RBRACE'):
                break
            stmt = self.parse_statement()
            if stmt:
                stmts.append(stmt)
            self.skip_semis()
        self.expect('RBRACE')
        return Block(stmts=stmts, line=tok.line, col=tok.col)

    # ── Statements ────────────────────────────────────────────────────────────

    def parse_statement(self) -> Optional[ASTNode]:
        tok = self.peek()
        if tok is None:
            return None

        kw = tok.value if tok.type == 'KEYWORD' else None

        if kw == 'if':     return self.parse_if_stmt()
        if kw == 'for':    return self.parse_for_stmt()
        if kw == 'while':  return self.parse_while_stmt()
        if kw == 'return': return self.parse_return_stmt()
        if kw == 'break':
            self.consume()
            self.skip_semis()
            return BreakStmt(line=tok.line, col=tok.col)
        if kw == 'continue':
            self.consume()
            self.skip_semis()
            return ContinueStmt(line=tok.line, col=tok.col)
        if kw == 'defer':  return self.parse_defer_stmt()
        if kw == 'go':     return self.parse_go_stmt()
        if kw == 'using':  return self.parse_using_stmt()
        if kw == 'match':  return self.parse_match_stmt()
        if kw == 'var':    return self.parse_var_decl()
        if kw == 'const':  return self.parse_const_decl()
        if tok.type == 'LBRACE': return self.parse_block()

        # Expression statement, short assign, or regular assign
        return self.parse_expr_or_assign_stmt()

    def parse_if_stmt(self) -> IfStmt:
        tok = self.expect('if')
        cond = self.parse_expression()
        then_body = self.parse_block()
        else_body = None
        if self.check('else'):
            self.consume()
            if self.check('if'):
                else_body = self.parse_if_stmt()
            else:
                else_body = self.parse_block()
        return IfStmt(cond=cond, then_body=then_body, else_body=else_body,
                      line=tok.line, col=tok.col)

    def parse_for_stmt(self) -> ASTNode:
        tok = self.expect('for')

        # Infinite loop: for { }
        if self.check('LBRACE'):
            body = self.parse_block()
            return ForStmt(cond=None, body=body, line=tok.line, col=tok.col)

        # Check for range: for IDENT in expr { }
        if self.peek() and self.peek().type == 'IDENT' and \
           self.peek(1) and self.peek(1).value == 'in':
            var_name = self.consume().value
            self.expect('in')
            iterable = self.parse_expression()
            body = self.parse_block()
            return ForInStmt(var=var_name, iterable=iterable, body=body,
                             line=tok.line, col=tok.col)

        # Regular: for condition { }
        cond = self.parse_expression()
        body = self.parse_block()
        return ForStmt(cond=cond, body=body, line=tok.line, col=tok.col)

    def parse_while_stmt(self) -> WhileStmt:
        tok = self.expect('while')
        cond = self.parse_expression()
        body = self.parse_block()
        return WhileStmt(cond=cond, body=body, line=tok.line, col=tok.col)

    def parse_return_stmt(self) -> ReturnStmt:
        tok = self.expect('return')
        values = []
        if not self.check('SEMI', 'RBRACE', 'NEWLINE') and not self.at_end():
            values.append(self.parse_expression())
            while self.match('COMMA'):
                values.append(self.parse_expression())
        self.skip_semis()
        return ReturnStmt(values=values, line=tok.line, col=tok.col)

    def parse_defer_stmt(self) -> DeferStmt:
        tok = self.expect('defer')
        expr = self.parse_expression()
        self.skip_semis()
        return DeferStmt(expr=expr, line=tok.line, col=tok.col)

    def parse_go_stmt(self) -> GoStmt:
        tok = self.expect('go')
        expr = self.parse_expression()
        self.skip_semis()
        return GoStmt(expr=expr, line=tok.line, col=tok.col)

    def parse_using_stmt(self) -> UsingStmt:
        tok = self.expect('using')
        expr = self.parse_expression()
        body = self.parse_block()
        return UsingStmt(expr=expr, body=body, line=tok.line, col=tok.col)

    def parse_match_stmt(self) -> MatchStmt:
        tok = self.expect('match')
        subject = self.parse_expression()
        self.expect('LBRACE')
        cases = []
        while not self.check('RBRACE') and not self.at_end():
            self.skip_semis()
            if self.check('RBRACE'):
                break
            case = self.parse_match_case()
            cases.append(case)
        self.expect('RBRACE')
        return MatchStmt(subject=subject, cases=cases,
                         line=tok.line, col=tok.col)

    def parse_match_case(self) -> MatchCase:
        tok = self.peek()
        pattern = None
        if self.check('default'):
            self.consume()
        elif self.check('case'):
            self.consume()
            pattern = self.parse_expression()
        else:
            raise ParseError(f"Expected 'case' or 'default'",
                             tok.line, tok.col)
        self.expect('COLON')
        body = self.parse_block()
        fallthrough = False
        if self.check('fallthrough'):
            self.consume()
            fallthrough = True
        self.skip_semis()
        return MatchCase(pattern=pattern, body=body, fallthrough=fallthrough,
                         line=tok.line, col=tok.col)

    def parse_expr_or_assign_stmt(self) -> ASTNode:
        """Parse:  expr  |  name := expr  |  targets = expr  |  targets op= expr"""
        left = self.parse_expression()
        tok = self.peek()

        # Short assign: name := expr
        if tok and tok.type == 'SHORT_ASSIGN':
            self.consume()
            if not isinstance(left, Identifier):
                raise ParseError("Left side of := must be an identifier",
                                 tok.line, tok.col)
            value = self.parse_expression()
            self.skip_semis()
            return ShortAssignStmt(name=left.name, value=value,
                                   line=tok.line, col=tok.col)

        # Compound / regular assignment
        assign_ops = ('ASSIGN', 'ADD_ASSIGN', 'SUB_ASSIGN', 'MUL_ASSIGN',
                      'DIV_ASSIGN', 'MOD_ASSIGN', 'AND_ASSIGN', 'OR_ASSIGN',
                      'XOR_ASSIGN', 'SHL_ASSIGN', 'SHR_ASSIGN')
        if tok and tok.type in assign_ops:
            op = tok.value
            self.consume()
            targets = [left]
            # Multi-target: a, b = x, y
            while self.check('COMMA'):
                self.consume()
                targets.append(self.parse_expression())
            values = [self.parse_expression()]
            while self.check('COMMA'):
                self.consume()
                values.append(self.parse_expression())
            self.skip_semis()
            return AssignStmt(targets=targets, op=op, values=values,
                              line=tok.line, col=tok.col)

        self.skip_semis()
        return ExprStmt(expr=left, line=left.line, col=left.col)

    # ── Expressions (Pratt precedence climbing) ───────────────────────────────

    # Precedence table: (token_type_or_value → (left_bp, right_bp))
    _INFIX_BP = {
        'OR':      (1, 2),
        'AND':     (3, 4),
        'PIPE':    (5, 6),
        'CARET':   (7, 8),
        'AMP':     (9, 10),
        'EQ':      (11, 12),
        'NEQ':     (11, 12),
        'LT':      (13, 14),
        'GT':      (13, 14),
        'LEQ':     (13, 14),
        'GEQ':     (13, 14),
        'SHL':     (15, 16),
        'SHR':     (15, 16),
        'PLUS':    (17, 18),
        'MINUS':   (17, 18),
        'STAR':    (19, 20),
        'SLASH':   (19, 20),
        'PERCENT': (19, 20),
    }

    def parse_expression(self, min_bp: int = 0) -> ASTNode:
        left = self.parse_unary()

        while True:
            tok = self.peek()
            if tok is None:
                break
            bp = self._INFIX_BP.get(tok.type)
            if bp is None or bp[0] <= min_bp:
                break
            self.consume()
            right = self.parse_expression(bp[1])
            left = BinaryExpr(op=tok.value, left=left, right=right,
                              line=tok.line, col=tok.col)

        return left

    def parse_unary(self) -> ASTNode:
        tok = self.peek()
        if tok and tok.type in ('BANG', 'MINUS', 'CARET', 'AMP', 'STAR'):
            self.consume()
            operand = self.parse_unary()
            return UnaryExpr(op=tok.value, operand=operand,
                             line=tok.line, col=tok.col)
        return self.parse_postfix()

    def parse_postfix(self) -> ASTNode:
        node = self.parse_primary()

        while True:
            tok = self.peek()
            if tok is None:
                break

            # Index: obj[expr]
            if tok.type == 'LBRACKET':
                self.consume()
                idx = self.parse_expression()
                self.expect('RBRACKET')
                node = IndexExpr(obj=node, index=idx,
                                 line=tok.line, col=tok.col)

            # Member: obj.field  or  obj->field
            elif tok.type in ('DOT', 'ARROW'):
                arrow = tok.type == 'ARROW'
                self.consume()
                member_tok = self.expect('IDENT')
                # Check for call: obj.method(args)
                if self.check('LPAREN'):
                    member_node = MemberExpr(obj=node, member=member_tok.value,
                                             arrow=arrow, line=tok.line, col=tok.col)
                    node = self._parse_call(member_node, tok)
                else:
                    node = MemberExpr(obj=node, member=member_tok.value,
                                      arrow=arrow, line=tok.line, col=tok.col)

            # Call: callee(args)
            elif tok.type == 'LPAREN':
                node = self._parse_call(node, tok)

            else:
                break

        return node

    def _parse_call(self, callee: ASTNode, tok: Token) -> CallExpr:
        self.expect('LPAREN')
        args = []
        while not self.check('RPAREN') and not self.at_end():
            args.append(self.parse_expression())
            if not self.match('COMMA'):
                break
        self.expect('RPAREN')
        return CallExpr(callee=callee, args=args, line=tok.line, col=tok.col)

    def parse_primary(self) -> ASTNode:
        tok = self.peek()
        if tok is None:
            raise ParseError("Unexpected end of expression", 0, 0)

        # Grouped expression
        if tok.type == 'LPAREN':
            self.consume()
            expr = self.parse_expression()
            self.expect('RPAREN')
            return expr

        # Slice literal: [a, b, c]
        if tok.type == 'LBRACKET':
            self.consume()
            elements = []
            while not self.check('RBRACKET') and not self.at_end():
                elements.append(self.parse_expression())
                if not self.match('COMMA'):
                    break
            self.expect('RBRACKET')
            return SliceLiteral(elements=elements, line=tok.line, col=tok.col)

        # Map literal: map{k: v, ...}
        if tok.value == 'map' and self.peek(1) and self.peek(1).type == 'LBRACE':
            self.consume()
            self.expect('LBRACE')
            pairs = []
            while not self.check('RBRACE') and not self.at_end():
                k = self.parse_expression()
                self.expect('COLON')
                v = self.parse_expression()
                pairs.append((k, v))
                if not self.match('COMMA'):
                    break
            self.expect('RBRACE')
            return MapLiteral(pairs=pairs, line=tok.line, col=tok.col)

        # make(chan T, cap)
        if tok.value == 'make':
            self.consume()
            self.expect('LPAREN')
            type_ref = self.parse_type()
            args = [type_ref]
            while self.match('COMMA'):
                args.append(self.parse_expression())
            self.expect('RPAREN')
            return MakeExpr(type_ref=type_ref, args=args,
                            line=tok.line, col=tok.col)

        # append(slice, val)
        if tok.value == 'append':
            self.consume()
            self.expect('LPAREN')
            sl = self.parse_expression()
            self.expect('COMMA')
            val = self.parse_expression()
            self.expect('RPAREN')
            return AppendExpr(slice_expr=sl, value_expr=val,
                              line=tok.line, col=tok.col)

        # Anonymous function literal: func(params) : ret { body }
        if tok.value == 'func':
            self.consume()
            params, returns = self.parse_params_and_returns()
            body = self.parse_block()
            return FuncLiteral(params=params, returns=returns, body=body,
                               line=tok.line, col=tok.col)

        # Boolean literals
        if tok.value == 'true':
            self.consume()
            return BoolLiteral(value=True, line=tok.line, col=tok.col)
        if tok.value == 'false':
            self.consume()
            return BoolLiteral(value=False, line=tok.line, col=tok.col)

        # Nil
        if tok.value == 'nil':
            self.consume()
            return NilLiteral(line=tok.line, col=tok.col)

        # Integer literal
        if tok.type == 'INT':
            self.consume()
            return IntLiteral(value=int(tok.value), line=tok.line, col=tok.col)

        # Float literal
        if tok.type == 'FLOAT':
            self.consume()
            return FloatLiteral(value=float(tok.value), line=tok.line, col=tok.col)

        # String literal
        if tok.type == 'STRING':
            self.consume()
            return StringLiteral(value=tok.value, line=tok.line, col=tok.col)

        # Identifier — could be struct literal: Name{...}
        if tok.type == 'IDENT':
            self.consume()
            # Struct literal: Identifier { field: val, ... }
            if self.check('LBRACE') and self.peek(1) and \
               self.peek(1).type == 'IDENT' and \
               self.peek(2) and self.peek(2).type == 'COLON':
                self.consume()  # {
                fields = []
                while not self.check('RBRACE') and not self.at_end():
                    fname = self.expect('IDENT')
                    self.expect('COLON')
                    fval  = self.parse_expression()
                    fields.append((fname.value, fval))
                    if not self.match('COMMA'):
                        break
                self.expect('RBRACE')
                return StructLiteral(type_name=tok.value, fields=fields,
                                     line=tok.line, col=tok.col)

            # Type cast: int(expr)
            if tok.value in ('int', 'uint', 'i8', 'i16', 'i32', 'u8', 'u16',
                              'u32', 'byte', 'rune', 'float32', 'float64',
                              'string', 'bool') and self.check('LPAREN'):
                self.consume()
                expr = self.parse_expression()
                self.expect('RPAREN')
                return TypeCast(target_type=tok.value, expr=expr,
                                line=tok.line, col=tok.col)

            return Identifier(name=tok.value, line=tok.line, col=tok.col)

        raise ParseError(f"Unexpected token {tok.value!r} ({tok.type})",
                         tok.line, tok.col)
