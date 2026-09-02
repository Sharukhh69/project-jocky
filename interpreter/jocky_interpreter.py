# jocky_interpreter.py — JOCKY Full Tree-Walk Interpreter
# Executes JOCKY source code directly without compilation.
# Supports the full language: functions, closures, goroutines, channels,
# defer, stdlib intrinsics, and all control-flow constructs.

from __future__ import annotations
import threading
import queue
import os
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple
from jocky_lexer import JockyLexer, LexerError
from jocky_parser import JockyParser, ParseError
from jocky_ast import *
from jocky_stdlib import build_stdlib, JockyError


# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME VALUES
# ─────────────────────────────────────────────────────────────────────────────

class JockyChannel:
    """Buffered or unbuffered channel (goroutine communication)."""
    def __init__(self, capacity: int = 0):
        self._q = queue.Queue(maxsize=capacity if capacity > 0 else 0)

    def send(self, val: Any):
        self._q.put(val)

    def recv(self) -> Any:
        return self._q.get()

    def try_recv(self) -> Tuple[Any, bool]:
        try:
            return self._q.get_nowait(), True
        except queue.Empty:
            return None, False


class JockyFunc:
    """A first-class JOCKY function value (closure)."""
    def __init__(self, decl: FuncDecl, closure: Dict[str, Any]):
        self.decl    = decl
        self.closure = closure  # captured variable bindings

    def __repr__(self):
        return f"<func {self.decl.name}>"


class ReturnSignal(Exception):
    def __init__(self, values):
        self.values = values


class BreakSignal(Exception):
    pass


class ContinueSignal(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT  (scoped variable store)
# ─────────────────────────────────────────────────────────────────────────────

class Environment:
    def __init__(self, parent: Optional['Environment'] = None):
        self._store:  Dict[str, Any] = {}
        self._parent: Optional[Environment] = parent

    def get(self, name: str) -> Any:
        if name in self._store:
            return self._store[name]
        if self._parent:
            return self._parent.get(name)
        raise JockyError(f"Undefined variable: {name!r}")

    def set(self, name: str, value: Any):
        """Set in the innermost scope that already owns the name."""
        if name in self._store:
            self._store[name] = value
        elif self._parent and self._parent._has(name):
            self._parent.set(name, value)
        else:
            self._store[name] = value

    def define(self, name: str, value: Any):
        """Always define in the current scope."""
        self._store[name] = value

    def _has(self, name: str) -> bool:
        if name in self._store:
            return True
        if self._parent:
            return self._parent._has(name)
        return False

    def child(self) -> 'Environment':
        return Environment(parent=self)


# ─────────────────────────────────────────────────────────────────────────────
# INTERPRETER
# ─────────────────────────────────────────────────────────────────────────────

class JockyInterpreter:
    """
    Full JOCKY tree-walk interpreter.

    Usage:
        interp = JockyInterpreter()
        interp.exec_source(source_code)
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stdlib  = build_stdlib()
        self.global_env = Environment()
        self._goroutines: List[threading.Thread] = []
        self._load_builtins()

    # ── Builtins ──────────────────────────────────────────────────────────────

    def _load_builtins(self):
        env = self.global_env

        # Stdlib modules as first-class values
        for name, mod in self.stdlib.items():
            env.define(name, mod)

        # Built-in functions
        env.define('len',    lambda *a: len(a[0]) if a else 0)
        env.define('cap',    lambda *a: len(a[0]) if a else 0)
        env.define('make',   self._builtin_make)
        env.define('append', lambda sl, v: (sl or []) + [v])
        env.define('print',  lambda *a: print(*a, end=''))
        env.define('println', lambda *a: print(*a))
        env.define('string', lambda v: str(v))
        env.define('int',    lambda v: int(v))
        env.define('float',  lambda v: float(v))
        env.define('bool',   lambda v: bool(v))
        env.define('byte',   lambda v: v & 0xFF if isinstance(v, int) else ord(v[0]))
        env.define('nil',    None)

    @staticmethod
    def _builtin_make(type_ref, *args):
        # make(chan T, cap) → JockyChannel
        # make([]T, len, cap) → list
        if isinstance(type_ref, str) and 'chan' in type_ref:
            cap = int(args[0]) if args else 0
            return JockyChannel(cap)
        # Default: return a list of zeroes
        length = int(args[0]) if args else 0
        return [None] * length

    # ── Public entry points ───────────────────────────────────────────────────

    def exec_source(self, source: str) -> Any:
        """Lex → Parse → Execute source code."""
        lexer   = JockyLexer()
        tokens  = lexer.tokenize(source)
        parser  = JockyParser(tokens)
        program = parser.parse()
        return self.exec_program(program)

    def exec_program(self, program: Program) -> Any:
        """Execute a fully-parsed Program."""
        env = self.global_env

        # Register all top-level function declarations first (hoisting)
        for fn_decl in program.functions:
            env.define(fn_decl.name,
                       JockyFunc(fn_decl, env._store.copy()))

        # Execute global statements / var declarations
        for stmt in program.globals:
            self.exec_stmt(stmt, env)

        # Call main() if it exists
        if env._has('main'):
            return self.call_func(env.get('main'), [], env)
        return None

    # ── Statement execution ───────────────────────────────────────────────────

    def exec_stmt(self, stmt: ASTNode, env: Environment) -> Any:
        if isinstance(stmt, VarDecl):
            val = self.eval_expr(stmt.value, env) if stmt.value is not None else None
            env.define(stmt.name, val)

        elif isinstance(stmt, ConstDecl):
            val = self.eval_expr(stmt.value, env)
            env.define(stmt.name, val)

        elif isinstance(stmt, ShortAssignStmt):
            val = self.eval_expr(stmt.value, env)
            env.define(stmt.name, val)

        elif isinstance(stmt, AssignStmt):
            values = [self.eval_expr(v, env) for v in stmt.values]
            for i, target in enumerate(stmt.targets):
                val = values[min(i, len(values)-1)]
                self._assign(target, val, stmt.op, env)

        elif isinstance(stmt, ExprStmt):
            self.eval_expr(stmt.expr, env)

        elif isinstance(stmt, ReturnStmt):
            vals = [self.eval_expr(v, env) for v in stmt.values]
            raise ReturnSignal(vals[0] if len(vals) == 1 else vals)

        elif isinstance(stmt, BreakStmt):
            raise BreakSignal()

        elif isinstance(stmt, ContinueStmt):
            raise ContinueSignal()

        elif isinstance(stmt, IfStmt):
            self.exec_if(stmt, env)

        elif isinstance(stmt, ForStmt):
            self.exec_for(stmt, env)

        elif isinstance(stmt, ForInStmt):
            self.exec_for_in(stmt, env)

        elif isinstance(stmt, WhileStmt):
            self.exec_while(stmt, env)

        elif isinstance(stmt, MatchStmt):
            self.exec_match(stmt, env)

        elif isinstance(stmt, DeferStmt):
            # Defer is attached to the current call frame — handled in call_func
            env.define('__defer__', getattr(env, '_defer_stack', []) +
                       [(stmt.expr, env)])
            env._defer_stack = env._store.get('__defer__', [])

        elif isinstance(stmt, GoStmt):
            expr = stmt.expr
            def _goroutine():
                try:
                    self.eval_expr(expr, env.child())
                except Exception:
                    pass
            t = threading.Thread(target=_goroutine, daemon=True)
            t.start()
            self._goroutines.append(t)

        elif isinstance(stmt, UsingStmt):
            # using resource { body }  — ensure cleanup
            resource = self.eval_expr(stmt.expr, env)
            child = env.child()
            try:
                self.exec_block(stmt.body, child)
            finally:
                if hasattr(resource, 'close'):
                    resource.close()

        elif isinstance(stmt, Block):
            self.exec_block(stmt, env.child())

        elif isinstance(stmt, FuncDecl):
            fn = JockyFunc(stmt, env._store.copy())
            env.define(stmt.name, fn)

    def exec_block(self, block: Block, env: Environment):
        defer_stack = []
        env._defer_stack = defer_stack
        try:
            for stmt in block.stmts:
                self.exec_stmt(stmt, env)
        finally:
            for expr, captured_env in reversed(defer_stack):
                try:
                    self.eval_expr(expr, captured_env)
                except Exception:
                    pass

    def exec_if(self, stmt: IfStmt, env: Environment):
        cond = self.eval_expr(stmt.cond, env)
        if self._truthy(cond):
            self.exec_block(stmt.then_body, env.child())
        elif stmt.else_body is not None:
            if isinstance(stmt.else_body, IfStmt):
                self.exec_if(stmt.else_body, env)
            else:
                self.exec_block(stmt.else_body, env.child())

    def exec_for(self, stmt: ForStmt, env: Environment):
        while True:
            if stmt.cond is not None:
                if not self._truthy(self.eval_expr(stmt.cond, env)):
                    break
            try:
                self.exec_block(stmt.body, env.child())
            except BreakSignal:
                break
            except ContinueSignal:
                continue

    def exec_for_in(self, stmt: ForInStmt, env: Environment):
        iterable = self.eval_expr(stmt.iterable, env)
        if iterable is None:
            return
        for item in iterable:
            child = env.child()
            child.define(stmt.var, item)
            try:
                self.exec_block(stmt.body, child)
            except BreakSignal:
                break
            except ContinueSignal:
                continue

    def exec_while(self, stmt: WhileStmt, env: Environment):
        while self._truthy(self.eval_expr(stmt.cond, env)):
            try:
                self.exec_block(stmt.body, env.child())
            except BreakSignal:
                break
            except ContinueSignal:
                continue

    def exec_match(self, stmt: MatchStmt, env: Environment):
        subject = self.eval_expr(stmt.subject, env)
        for case in stmt.cases:
            if case.pattern is None:   # default
                self.exec_block(case.body, env.child())
                if not case.fallthrough:
                    return
            else:
                pattern_val = self.eval_expr(case.pattern, env)
                if subject == pattern_val:
                    self.exec_block(case.body, env.child())
                    if not case.fallthrough:
                        return

    # ── Expression evaluation ─────────────────────────────────────────────────

    def eval_expr(self, expr: ASTNode, env: Environment) -> Any:
        if expr is None:
            return None

        if isinstance(expr, IntLiteral):
            return expr.value

        if isinstance(expr, FloatLiteral):
            return expr.value

        if isinstance(expr, StringLiteral):
            return expr.value

        if isinstance(expr, BoolLiteral):
            return expr.value

        if isinstance(expr, NilLiteral):
            return None

        if isinstance(expr, SliceLiteral):
            return [self.eval_expr(e, env) for e in expr.elements]

        if isinstance(expr, MapLiteral):
            return {self.eval_expr(k, env): self.eval_expr(v, env)
                    for k, v in expr.pairs}

        if isinstance(expr, StructLiteral):
            obj = {}
            for fname, fval in expr.fields:
                obj[fname] = self.eval_expr(fval, env)
            return obj

        if isinstance(expr, Identifier):
            return env.get(expr.name)

        if isinstance(expr, BinaryExpr):
            return self.eval_binary(expr, env)

        if isinstance(expr, UnaryExpr):
            return self.eval_unary(expr, env)

        if isinstance(expr, MemberExpr):
            obj = self.eval_expr(expr.obj, env)
            return self._get_member(obj, expr.member)

        if isinstance(expr, IndexExpr):
            obj = self.eval_expr(expr.obj, env)
            idx = self.eval_expr(expr.index, env)
            if isinstance(obj, (list, bytes, bytearray)):
                return obj[int(idx)]
            if isinstance(obj, dict):
                return obj.get(idx)
            if isinstance(obj, str):
                return obj[int(idx)]
            return None

        if isinstance(expr, CallExpr):
            return self.eval_call(expr, env)

        if isinstance(expr, AppendExpr):
            sl  = self.eval_expr(expr.slice_expr, env)
            val = self.eval_expr(expr.value_expr, env)
            if sl is None:
                sl = []
            return sl + [val]

        if isinstance(expr, TypeCast):
            val = self.eval_expr(expr.expr, env)
            return self._cast(val, expr.target_type)

        if isinstance(expr, MakeExpr):
            return self._builtin_make(
                getattr(expr.type_ref, 'name', str(expr.type_ref)),
                *[self.eval_expr(a, env) for a in expr.args]
            )

        if isinstance(expr, FuncLiteral):
            return JockyFunc(
                FuncDecl(name="<anonymous>", params=expr.params,
                         returns=expr.returns, body=expr.body),
                env._store.copy()
            )

        raise JockyError(f"Unknown expression: {type(expr).__name__}")

    def eval_binary(self, expr: BinaryExpr, env: Environment) -> Any:
        # Short-circuit for logical operators
        if expr.op == '&&':
            l = self.eval_expr(expr.left, env)
            return l if not self._truthy(l) else self.eval_expr(expr.right, env)
        if expr.op == '||':
            l = self.eval_expr(expr.left, env)
            return l if self._truthy(l) else self.eval_expr(expr.right, env)

        l = self.eval_expr(expr.left, env)
        r = self.eval_expr(expr.right, env)

        op = expr.op
        if op == '+':
            if isinstance(l, str) or isinstance(r, str):
                return str(l) + str(r)
            return l + r
        if op == '-':  return l - r
        if op == '*':  return l * r
        if op == '/':
            if r == 0:
                raise JockyError("Division by zero")
            return l // r if isinstance(l, int) and isinstance(r, int) else l / r
        if op == '%':  return l % r
        if op == '==': return l == r
        if op == '!=': return l != r
        if op == '<':  return l < r
        if op == '>':  return l > r
        if op == '<=': return l <= r
        if op == '>=': return l >= r
        if op == '&':  return int(l) & int(r)
        if op == '|':  return int(l) | int(r)
        if op == '^':  return int(l) ^ int(r)
        if op == '<<': return int(l) << int(r)
        if op == '>>': return int(l) >> int(r)
        raise JockyError(f"Unknown operator: {op!r}")

    def eval_unary(self, expr: UnaryExpr, env: Environment) -> Any:
        val = self.eval_expr(expr.operand, env)
        op  = expr.op
        if op == '!':  return not self._truthy(val)
        if op == '-':  return -val
        if op == '^':  return ~int(val)
        if op == '&':  return id(val)    # address-of (simulated)
        if op == '*':  return val        # dereference (simulated)
        raise JockyError(f"Unknown unary operator: {op!r}")

    def eval_call(self, expr: CallExpr, env: Environment) -> Any:
        # module.method(args)
        if isinstance(expr.callee, MemberExpr):
            obj  = self.eval_expr(expr.callee.obj, env)
            meth = expr.callee.member
            args = [self.eval_expr(a, env) for a in expr.args]

            if isinstance(obj, dict):
                fn = obj.get(meth)
                if fn is None:
                    raise JockyError(f"No method {meth!r} on struct")
                return self._call_value(fn, args, env)

            # stdlib module
            if hasattr(obj, meth):
                fn = getattr(obj, meth)
                try:
                    return fn(*args)
                except JockyError:
                    raise
                except Exception as e:
                    raise JockyError(f"{type(obj).__name__}.{meth}: {e}")

            raise JockyError(f"No method {meth!r} on {type(obj).__name__}")

        # Direct call
        callee = self.eval_expr(expr.callee, env)
        args   = [self.eval_expr(a, env) for a in expr.args]
        return self._call_value(callee, args, env)

    def _call_value(self, callee: Any, args: List[Any], env: Environment) -> Any:
        if isinstance(callee, JockyFunc):
            return self.call_func(callee, args, env)
        if callable(callee):
            return callee(*args)
        raise JockyError(f"Not callable: {callee!r}")

    def call_func(self, fn: JockyFunc, args: List[Any],
                  caller_env: Environment) -> Any:
        # Build function environment from closure
        fn_env = Environment()
        fn_env._store.update(fn.closure)
        fn_env._store.update(self.global_env._store)

        # Bind parameters
        for i, param in enumerate(fn.decl.params):
            if param.variadic:
                fn_env.define(param.name, list(args[i:]))
            elif i < len(args):
                fn_env.define(param.name, args[i])
            else:
                fn_env.define(param.name, None)

        defer_stack = []
        fn_env._defer_stack = defer_stack

        try:
            if fn.decl.body:
                self.exec_block(fn.decl.body, fn_env)
            return None
        except ReturnSignal as ret:
            return ret.values
        finally:
            for expr, captured_env in reversed(defer_stack):
                try:
                    self.eval_expr(expr, captured_env)
                except Exception:
                    pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _truthy(val: Any) -> bool:
        if val is None:   return False
        if val is False:  return False
        if val == 0:      return False
        if val == "":     return False
        if isinstance(val, (list, dict, bytes)) and len(val) == 0:
            return False
        return True

    @staticmethod
    def _get_member(obj: Any, member: str) -> Any:
        if isinstance(obj, dict):
            return obj.get(member)
        if hasattr(obj, member):
            return getattr(obj, member)
        return None

    def _assign(self, target: ASTNode, val: Any, op: str, env: Environment):
        if isinstance(target, Identifier):
            if op == '=':
                env.set(target.name, val)
            else:
                old = env.get(target.name)
                env.set(target.name, self._apply_op(old, op, val))
        elif isinstance(target, MemberExpr):
            obj = self.eval_expr(target.obj, env)
            if isinstance(obj, dict):
                if op == '=':
                    obj[target.member] = val
                else:
                    obj[target.member] = self._apply_op(
                        obj.get(target.member), op, val)
        elif isinstance(target, IndexExpr):
            obj = self.eval_expr(target.obj, env)
            idx = self.eval_expr(target.index, env)
            if isinstance(obj, list):
                obj[int(idx)] = val
            elif isinstance(obj, dict):
                obj[idx] = val

    @staticmethod
    def _apply_op(old: Any, op: str, val: Any) -> Any:
        if op == '+=': return old + val
        if op == '-=': return old - val
        if op == '*=': return old * val
        if op == '/=': return old / val if val != 0 else 0
        if op == '%=': return old % val
        if op == '&=': return int(old) & int(val)
        if op == '|=': return int(old) | int(val)
        if op == '^=': return int(old) ^ int(val)
        if op == '<<=': return int(old) << int(val)
        if op == '>>=': return int(old) >> int(val)
        return val

    @staticmethod
    def _cast(val: Any, target: str) -> Any:
        try:
            if target in ('int', 'i8', 'i16', 'i32', 'i64',
                          'uint', 'u8', 'u16', 'u32', 'u64', 'byte'):
                return int(val)
            if target in ('float', 'float32', 'float64'):
                return float(val)
            if target == 'string':
                return str(val) if not isinstance(val, bytes) \
                    else val.decode(errors='replace')
            if target == 'bool':
                return bool(val)
        except Exception:
            pass
        return val

    def wait_goroutines(self, timeout: float = 5.0):
        """Join all spawned goroutines."""
        for t in self._goroutines:
            t.join(timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION HELPER  (public API for the web UI)
# ─────────────────────────────────────────────────────────────────────────────

def validate_jocky_script(source: str) -> dict:
    """
    Validate JOCKY source without executing.
    Returns {"valid": bool, "errors": [str], "ast_nodes": int, "tokens": int}
    """
    try:
        lexer   = JockyLexer()
        tokens  = lexer.tokenize(source)
        parser  = JockyParser(tokens)
        program = parser.parse()
        total   = (len(program.functions) + len(program.structs) +
                   len(program.globals) + len(program.imports))
        return {
            "valid":     True,
            "errors":    [],
            "ast_nodes": total,
            "tokens":    len(tokens),
            "functions": len(program.functions),
            "imports":   len(program.imports),
            "structs":   len(program.structs),
        }
    except (LexerError, ParseError, JockyError) as e:
        return {"valid": False, "errors": [str(e)]}


def run_jocky_script(source: str, verbose: bool = False) -> Any:
    """
    Full pipeline: source → tokens → AST → execution.
    Returns the result of main() or the last expression.
    """
    interp = JockyInterpreter(verbose=verbose)
    result = interp.exec_source(source)
    interp.wait_goroutines()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    sample = r"""
module forensics_demo

func greet(name: string) {
    fmt.println("Hello,", name)
}

func add(a: int, b: int) : int {
    return a + b
}

func main() {
    greet("JOCKY")

    x := 10
    y := 20
    z := add(x, y)
    fmt.println("10 + 20 =", z)

    primes := [2, 3, 5, 7, 11, 13]
    for p in primes {
        fmt.println("prime:", p)
    }

    i := 0
    while i < 3 {
        fmt.println("i =", i)
        i += 1
    }

    pid := sys.getpid()
    fmt.println("PID:", pid)

    host := sys.hostname()
    fmt.println("Hostname:", host)

    fmt.println("Done.")
}
"""
    print("=== JOCKY INTERPRETER — Self Test ===\n")
    result = validate_jocky_script(sample)
    print(f"  Valid:     {result['valid']}")
    print(f"  Tokens:    {result.get('tokens')}")
    print(f"  AST nodes: {result.get('ast_nodes')}")
    print(f"  Functions: {result.get('functions')}")
    print()
    print("=== Execution ===\n")
    run_jocky_script(sample, verbose=True)
