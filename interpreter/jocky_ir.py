# jocky_ir.py — JOCKY Intermediate Representation (JOCKY-IR)
# SSA-based IR with custom instructions for forensic/evasion operations.
# The AST is lowered to this IR; the IR is then lowered to LLVM IR or
# interpreted directly.

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import hashlib, random


# ─────────────────────────────────────────────────────────────────────────────
# VALUE TYPES IN IR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IRType:
    name: str  # int, float, bool, string, ptr, bytes, void, any

IR_INT    = IRType('int')
IR_FLOAT  = IRType('float')
IR_BOOL   = IRType('bool')
IR_STRING = IRType('string')
IR_BYTES  = IRType('bytes')
IR_PTR    = IRType('ptr')
IR_VOID   = IRType('void')
IR_ANY    = IRType('any')


# ─────────────────────────────────────────────────────────────────────────────
# IR VALUES  (SSA names)
# ─────────────────────────────────────────────────────────────────────────────

_ssa_counter = 0

def fresh_name(prefix: str = 'v') -> str:
    global _ssa_counter
    _ssa_counter += 1
    return f'%{prefix}{_ssa_counter}'


@dataclass
class IRValue:
    name:  str
    type:  IRType


@dataclass
class IRConst(IRValue):
    literal: Any = None


# ─────────────────────────────────────────────────────────────────────────────
# IR INSTRUCTIONS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IRInstr:
    """Base IR instruction."""
    comment: str = ""


@dataclass
class IRAlloc(IRInstr):
    """dest = alloc type    — allocate a local slot"""
    dest: str = ""
    type: IRType = field(default_factory=lambda: IR_ANY)


@dataclass
class IRStore(IRInstr):
    """store value → dest_ptr"""
    dest: str = ""
    src:  str = ""


@dataclass
class IRLoad(IRInstr):
    """dest = load src_ptr"""
    dest: str = ""
    src:  str = ""


@dataclass
class IRBinOp(IRInstr):
    """dest = op left right"""
    dest:  str = ""
    op:    str = ""    # +, -, *, /, %, ==, !=, <, >, <=, >=, &&, ||, &, |, ^
    left:  str = ""
    right: str = ""


@dataclass
class IRUnaryOp(IRInstr):
    """dest = op operand"""
    dest:    str = ""
    op:      str = ""
    operand: str = ""


@dataclass
class IRConst_(IRInstr):
    """dest = const value"""
    dest:  str = ""
    value: Any = None
    type:  IRType = field(default_factory=lambda: IR_ANY)


@dataclass
class IRCall(IRInstr):
    """dest = call fn(args...)"""
    dest:    str = ""
    fn:      str = ""    # function name or label
    args:    List[str] = field(default_factory=list)
    returns: bool = True  # False → void call


@dataclass
class IRCallIntrinsic(IRInstr):
    """dest = intrinsic module.fn(args...)  — stdlib call"""
    dest:   str = ""
    module: str = ""
    fn:     str = ""
    args:   List[str] = field(default_factory=list)


@dataclass
class IRSyscall(IRInstr):
    """dest, err = syscall(number, args...)"""
    dest:   str = ""
    err:    str = ""
    number: str = ""   # value name or const
    args:   List[str] = field(default_factory=list)


@dataclass
class IRBranch(IRInstr):
    """branch cond → true_label | false_label"""
    cond:        str = ""
    true_label:  str = ""
    false_label: str = ""


@dataclass
class IRJump(IRInstr):
    """jump → label"""
    label: str = ""


@dataclass
class IRReturn(IRInstr):
    """return values"""
    values: List[str] = field(default_factory=list)


@dataclass
class IRPhi(IRInstr):
    """dest = phi [(val, label), ...]  — SSA merge"""
    dest:    str = ""
    options: List[tuple] = field(default_factory=list)  # [(val_name, block_label)]


@dataclass
class IRIndex(IRInstr):
    """dest = index obj[idx]"""
    dest: str = ""
    obj:  str = ""
    idx:  str = ""


@dataclass
class IRMember(IRInstr):
    """dest = member obj.field"""
    dest:   str = ""
    obj:    str = ""
    field:  str = ""


@dataclass
class IRSetMember(IRInstr):
    """set obj.field = value"""
    obj:   str = ""
    field: str = ""
    value: str = ""


@dataclass
class IRMakeSlice(IRInstr):
    """dest = makeslice type len cap"""
    dest:    str = ""
    elem_ty: IRType = field(default_factory=lambda: IR_ANY)


@dataclass
class IRAppend(IRInstr):
    """dest = append slice value"""
    dest:  str = ""
    slice: str = ""
    value: str = ""


@dataclass
class IRGo(IRInstr):
    """go fn(args)  — spawn goroutine"""
    fn:   str = ""
    args: List[str] = field(default_factory=list)


@dataclass
class IRDefer(IRInstr):
    """defer fn(args)"""
    fn:   str = ""
    args: List[str] = field(default_factory=list)


@dataclass
class IRObfuscateAttr(IRInstr):
    """@obfuscate marker — triggers obfuscation pass"""
    target: str = ""


@dataclass
class IREncryptAttr(IRInstr):
    """@encrypt marker — marks a value for encryption at rest"""
    target: str = ""
    key:    str = ""


@dataclass
class IRPolymorphicAttr(IRInstr):
    """@polymorphic marker — triggers CFG mutation for enclosing function"""
    fn_name: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# BASIC BLOCK
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    label:  str
    instrs: List[IRInstr] = field(default_factory=list)
    # CFG edges (filled by builder)
    succs:  List[str] = field(default_factory=list)

    def append(self, instr: IRInstr):
        self.instrs.append(instr)

    def is_terminated(self) -> bool:
        if not self.instrs:
            return False
        last = self.instrs[-1]
        return isinstance(last, (IRReturn, IRJump, IRBranch))


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IRFunction:
    name:       str
    params:     List[tuple]      = field(default_factory=list)  # (name, IRType)
    ret_types:  List[IRType]     = field(default_factory=list)
    blocks:     List[BasicBlock] = field(default_factory=list)
    attributes: List[str]        = field(default_factory=list)  # @polymorphic etc.

    @property
    def entry(self) -> Optional[BasicBlock]:
        return self.blocks[0] if self.blocks else None

    def new_block(self, label: str = None) -> BasicBlock:
        if label is None:
            label = f"bb{len(self.blocks)}"
        bb = BasicBlock(label=label)
        self.blocks.append(bb)
        return bb

    def dump(self) -> str:
        lines = [f"func {self.name}({', '.join(n for n,_ in self.params)}):"]
        for bb in self.blocks:
            lines.append(f"  {bb.label}:")
            for instr in bb.instrs:
                lines.append(f"    {instr}")
        return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IRModule:
    name:      str
    functions: List[IRFunction]   = field(default_factory=list)
    globals:   List[IRInstr]      = field(default_factory=list)  # global consts/vars
    build_id:  str                = ""

    def dump(self) -> str:
        lines = [f"; JOCKY-IR Module: {self.name}",
                 f"; Build ID: {self.build_id}", ""]
        for fn in self.functions:
            lines.append(fn.dump())
            lines.append("")
        return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# IR BUILDER  — lowers AST → JOCKY-IR
# ─────────────────────────────────────────────────────────────────────────────

import time as _time

class IRBuilder:
    """
    Walks the JOCKY AST and emits JOCKY-IR.

    Usage:
        builder = IRBuilder()
        ir_mod  = builder.build(program_ast, module_name="forensics")
    """

    def __init__(self):
        self.module:  Optional[IRModule] = None
        self.cur_fn:  Optional[IRFunction] = None
        self.cur_bb:  Optional[BasicBlock]  = None
        self._env:    List[Dict[str, str]] = []   # stack of name→ssa_name scopes
        self._loop_exits: List[str] = []
        self._loop_continues: List[str] = []

    # ── public entry ──────────────────────────────────────────────────────────

    def build(self, program, module_name: str = "jocky") -> IRModule:
        from jocky_ast import (Program, FuncDecl, ConstDecl, VarDecl)

        build_id = hashlib.sha256(
            (module_name + str(_time.time()) + str(random.random())).encode()
        ).hexdigest()[:12]

        self.module = IRModule(name=module_name, build_id=build_id)
        self._env = [{}]

        # Emit globals
        for g in program.globals:
            if isinstance(g, ConstDecl):
                v = fresh_name('c')
                self.module.globals.append(
                    IRConst_(dest=v, value=g.name, type=IR_ANY,
                             comment=f"const {g.name}"))
                self._env[0][g.name] = v

        # Emit functions
        for fn_decl in program.functions:
            self._build_function(fn_decl)

        return self.module

    # ── function ──────────────────────────────────────────────────────────────

    def _build_function(self, fn_decl):
        from jocky_ast import FuncDecl

        params = []
        for p in fn_decl.params:
            p_name = fresh_name('p')
            params.append((p_name, IR_ANY))

        ir_fn = IRFunction(
            name=fn_decl.name,
            params=params,
            attributes=fn_decl.attributes,
        )
        self.module.functions.append(ir_fn)
        self.cur_fn = ir_fn

        # Mark @polymorphic
        if 'polymorphic' in fn_decl.attributes:
            ir_fn.attributes.append('polymorphic')

        # Create entry block
        entry = ir_fn.new_block('entry')
        self.cur_bb = entry

        # Bind params in scope
        self._env.append({})
        for i, p_decl in enumerate(fn_decl.params):
            self._env[-1][p_decl.name] = params[i][0]

        # Emit body
        if fn_decl.body:
            self._build_block(fn_decl.body)

        # Ensure block is terminated
        if self.cur_bb and not self.cur_bb.is_terminated():
            self.cur_bb.append(IRReturn(values=[]))

        self._env.pop()
        self.cur_fn = None
        self.cur_bb = None

    # ── block & statements ────────────────────────────────────────────────────

    def _build_block(self, block):
        from jocky_ast import (Block, IfStmt, ForStmt, ForInStmt, WhileStmt,
                                ReturnStmt, BreakStmt, ContinueStmt,
                                DeferStmt, GoStmt, UsingStmt, MatchStmt,
                                VarDecl, ConstDecl, ExprStmt, AssignStmt,
                                ShortAssignStmt)
        for stmt in block.stmts:
            self._build_stmt(stmt)

    def _build_stmt(self, stmt):
        from jocky_ast import (IfStmt, ForStmt, ForInStmt, WhileStmt,
                                ReturnStmt, BreakStmt, ContinueStmt,
                                DeferStmt, GoStmt, UsingStmt, MatchStmt,
                                VarDecl, ConstDecl, ExprStmt, AssignStmt,
                                ShortAssignStmt, Block)

        if isinstance(stmt, ShortAssignStmt):
            v = self._build_expr(stmt.value)
            dest = fresh_name('v')
            self.emit(IRStore(dest=dest, src=v))
            self._define(stmt.name, dest)

        elif isinstance(stmt, VarDecl):
            dest = fresh_name('var')
            self.emit(IRAlloc(dest=dest, type=IR_ANY))
            self._define(stmt.name, dest)
            if stmt.value:
                v = self._build_expr(stmt.value)
                self.emit(IRStore(dest=dest, src=v))

        elif isinstance(stmt, ConstDecl):
            v = fresh_name('c')
            val = self._build_expr(stmt.value)
            self.emit(IRConst_(dest=v, value=val, type=IR_ANY))
            self._define(stmt.name, v)

        elif isinstance(stmt, AssignStmt):
            for i, target in enumerate(stmt.targets):
                val = self._build_expr(stmt.values[min(i, len(stmt.values)-1)])
                self._assign_target(target, val, stmt.op)

        elif isinstance(stmt, ReturnStmt):
            vals = [self._build_expr(v) for v in stmt.values]
            self.emit(IRReturn(values=vals))

        elif isinstance(stmt, IfStmt):
            self._build_if(stmt)

        elif isinstance(stmt, ForStmt):
            self._build_for(stmt)

        elif isinstance(stmt, ForInStmt):
            self._build_for_in(stmt)

        elif isinstance(stmt, WhileStmt):
            self._build_while(stmt)

        elif isinstance(stmt, DeferStmt):
            fn_name, args = self._expr_to_call(stmt.expr)
            self.emit(IRDefer(fn=fn_name, args=args))

        elif isinstance(stmt, GoStmt):
            fn_name, args = self._expr_to_call(stmt.expr)
            self.emit(IRGo(fn=fn_name, args=args))

        elif isinstance(stmt, ExprStmt):
            self._build_expr(stmt.expr)

        elif isinstance(stmt, Block):
            self._env.append({})
            self._build_block(stmt)
            self._env.pop()

        elif isinstance(stmt, BreakStmt):
            if self._loop_exits:
                self.emit(IRJump(label=self._loop_exits[-1]))

        elif isinstance(stmt, ContinueStmt):
            if self._loop_continues:
                self.emit(IRJump(label=self._loop_continues[-1]))

    # ── control flow helpers ──────────────────────────────────────────────────

    def _build_if(self, stmt):
        cond = self._build_expr(stmt.cond)
        then_lbl = f"if_then_{fresh_name('b')[1:]}"
        else_lbl = f"if_else_{fresh_name('b')[1:]}"
        end_lbl  = f"if_end_{fresh_name('b')[1:]}"

        self.emit(IRBranch(cond=cond,
                           true_label=then_lbl,
                           false_label=else_lbl if stmt.else_body else end_lbl))

        # then
        self._new_block(then_lbl)
        self._env.append({})
        self._build_block(stmt.then_body)
        self._env.pop()
        if not self.cur_bb.is_terminated():
            self.emit(IRJump(label=end_lbl))

        # else
        if stmt.else_body:
            self._new_block(else_lbl)
            self._env.append({})
            from jocky_ast import IfStmt, Block
            if isinstance(stmt.else_body, IfStmt):
                self._build_if(stmt.else_body)
            else:
                self._build_block(stmt.else_body)
            self._env.pop()
            if not self.cur_bb.is_terminated():
                self.emit(IRJump(label=end_lbl))

        self._new_block(end_lbl)

    def _build_for(self, stmt):
        cond_lbl = f"for_cond_{fresh_name('b')[1:]}"
        body_lbl = f"for_body_{fresh_name('b')[1:]}"
        end_lbl  = f"for_end_{fresh_name('b')[1:]}"

        self._loop_exits.append(end_lbl)
        self._loop_continues.append(cond_lbl)

        self.emit(IRJump(label=cond_lbl))
        self._new_block(cond_lbl)

        if stmt.cond:
            cond = self._build_expr(stmt.cond)
            self.emit(IRBranch(cond=cond, true_label=body_lbl,
                               false_label=end_lbl))
        else:
            self.emit(IRJump(label=body_lbl))

        self._new_block(body_lbl)
        self._env.append({})
        self._build_block(stmt.body)
        self._env.pop()
        if not self.cur_bb.is_terminated():
            self.emit(IRJump(label=cond_lbl))

        self._new_block(end_lbl)
        self._loop_exits.pop()
        self._loop_continues.pop()

    def _build_for_in(self, stmt):
        iter_val = self._build_expr(stmt.iterable)
        idx_dest = fresh_name('idx')
        end_lbl  = f"forin_end_{fresh_name('b')[1:]}"
        body_lbl = f"forin_body_{fresh_name('b')[1:]}"

        self.emit(IRConst_(dest=idx_dest, value=0, type=IR_INT))
        self.emit(IRJump(label=body_lbl))
        self._new_block(body_lbl)

        # item = iter_val[idx]
        item_dest = fresh_name('item')
        self.emit(IRIndex(dest=item_dest, obj=iter_val, idx=idx_dest))

        self._loop_exits.append(end_lbl)
        self._loop_continues.append(body_lbl)

        self._env.append({stmt.var: item_dest})
        self._build_block(stmt.body)
        self._env.pop()

        if not self.cur_bb.is_terminated():
            self.emit(IRJump(label=end_lbl))

        self._new_block(end_lbl)
        self._loop_exits.pop()
        self._loop_continues.pop()

    def _build_while(self, stmt):
        cond_lbl = f"while_cond_{fresh_name('b')[1:]}"
        body_lbl = f"while_body_{fresh_name('b')[1:]}"
        end_lbl  = f"while_end_{fresh_name('b')[1:]}"

        self._loop_exits.append(end_lbl)
        self._loop_continues.append(cond_lbl)

        self.emit(IRJump(label=cond_lbl))
        self._new_block(cond_lbl)
        cond = self._build_expr(stmt.cond)
        self.emit(IRBranch(cond=cond, true_label=body_lbl, false_label=end_lbl))

        self._new_block(body_lbl)
        self._env.append({})
        self._build_block(stmt.body)
        self._env.pop()
        if not self.cur_bb.is_terminated():
            self.emit(IRJump(label=cond_lbl))

        self._new_block(end_lbl)
        self._loop_exits.pop()
        self._loop_continues.pop()

    # ── expression lowering ───────────────────────────────────────────────────

    def _build_expr(self, expr) -> str:
        from jocky_ast import (BinaryExpr, UnaryExpr, CallExpr, MemberExpr,
                                IndexExpr, Identifier, IntLiteral, FloatLiteral,
                                StringLiteral, BoolLiteral, NilLiteral,
                                SliceLiteral, MapLiteral, AppendExpr,
                                TypeCast, MakeExpr, FuncLiteral, StructLiteral)

        if isinstance(expr, IntLiteral):
            d = fresh_name('i')
            self.emit(IRConst_(dest=d, value=expr.value, type=IR_INT))
            return d

        if isinstance(expr, FloatLiteral):
            d = fresh_name('f')
            self.emit(IRConst_(dest=d, value=expr.value, type=IR_FLOAT))
            return d

        if isinstance(expr, StringLiteral):
            d = fresh_name('s')
            self.emit(IRConst_(dest=d, value=expr.value, type=IR_STRING))
            return d

        if isinstance(expr, BoolLiteral):
            d = fresh_name('b')
            self.emit(IRConst_(dest=d, value=expr.value, type=IR_BOOL))
            return d

        if isinstance(expr, NilLiteral):
            d = fresh_name('n')
            self.emit(IRConst_(dest=d, value=None, type=IR_PTR))
            return d

        if isinstance(expr, Identifier):
            return self._lookup(expr.name)

        if isinstance(expr, BinaryExpr):
            l = self._build_expr(expr.left)
            r = self._build_expr(expr.right)
            d = fresh_name('r')
            self.emit(IRBinOp(dest=d, op=expr.op, left=l, right=r))
            return d

        if isinstance(expr, UnaryExpr):
            o = self._build_expr(expr.operand)
            d = fresh_name('u')
            self.emit(IRUnaryOp(dest=d, op=expr.op, operand=o))
            return d

        if isinstance(expr, MemberExpr):
            obj = self._build_expr(expr.obj)
            d   = fresh_name('m')
            self.emit(IRMember(dest=d, obj=obj, field=expr.member))
            return d

        if isinstance(expr, IndexExpr):
            obj = self._build_expr(expr.obj)
            idx = self._build_expr(expr.index)
            d   = fresh_name('x')
            self.emit(IRIndex(dest=d, obj=obj, idx=idx))
            return d

        if isinstance(expr, CallExpr):
            return self._build_call(expr)

        if isinstance(expr, AppendExpr):
            sl  = self._build_expr(expr.slice_expr)
            val = self._build_expr(expr.value_expr)
            d   = fresh_name('app')
            self.emit(IRAppend(dest=d, slice=sl, value=val))
            return d

        if isinstance(expr, TypeCast):
            v = self._build_expr(expr.expr)
            d = fresh_name('cast')
            self.emit(IRUnaryOp(dest=d, op=f'cast:{expr.target_type}', operand=v))
            return d

        if isinstance(expr, SliceLiteral):
            d = fresh_name('sl')
            self.emit(IRMakeSlice(dest=d, elem_ty=IR_ANY))
            for elem in expr.elements:
                ev = self._build_expr(elem)
                self.emit(IRAppend(dest=d, slice=d, value=ev))
            return d

        # Fallback
        d = fresh_name('?')
        self.emit(IRConst_(dest=d, value=None, type=IR_ANY,
                            comment=f"unhandled expr: {type(expr).__name__}"))
        return d

    def _build_call(self, expr) -> str:
        from jocky_ast import MemberExpr, Identifier

        # module.method(args) — stdlib intrinsic
        if isinstance(expr.callee, MemberExpr):
            obj = expr.callee.obj
            if isinstance(obj, MemberExpr):
                # e.g. proc.list() — obj is already Identifier
                module_name = self._member_path(obj)
            elif isinstance(obj, Identifier):
                module_name = obj.name
            else:
                module_name = self._build_expr(obj)

            method = expr.callee.member
            args = [self._build_expr(a) for a in expr.args]
            d = fresh_name('ret')
            self.emit(IRCallIntrinsic(dest=d, module=module_name,
                                       fn=method, args=args))
            return d

        # Direct function call
        callee_name = ""
        if isinstance(expr.callee, Identifier):
            callee_name = expr.callee.name
        else:
            callee_name = self._build_expr(expr.callee)

        args = [self._build_expr(a) for a in expr.args]
        d = fresh_name('ret')
        self.emit(IRCall(dest=d, fn=callee_name, args=args))
        return d

    def _member_path(self, expr) -> str:
        from jocky_ast import MemberExpr, Identifier
        if isinstance(expr, Identifier):
            return expr.name
        if isinstance(expr, MemberExpr):
            return self._member_path(expr.obj) + '.' + expr.member
        return '?'

    def _assign_target(self, target, val: str, op: str):
        from jocky_ast import Identifier, MemberExpr, IndexExpr
        if isinstance(target, Identifier):
            ptr = self._lookup_ptr(target.name)
            if op != '=':
                old = fresh_name('old')
                self.emit(IRLoad(dest=old, src=ptr))
                new = fresh_name('new')
                op_char = op[0]  # += → +
                self.emit(IRBinOp(dest=new, op=op_char, left=old, right=val))
                val = new
            self.emit(IRStore(dest=ptr, src=val))
        elif isinstance(target, MemberExpr):
            obj = self._build_expr(target.obj)
            self.emit(IRSetMember(obj=obj, field=target.member, value=val))

    # ── scope helpers ─────────────────────────────────────────────────────────

    def _define(self, name: str, ssa_name: str):
        self._env[-1][name] = ssa_name

    def _lookup(self, name: str) -> str:
        for scope in reversed(self._env):
            if name in scope:
                return scope[name]
        # Return as constant name (might be a function or global)
        d = fresh_name('ref')
        self.emit(IRConst_(dest=d, value=name, type=IR_ANY,
                            comment=f"ref to {name!r}"))
        return d

    def _lookup_ptr(self, name: str) -> str:
        for scope in reversed(self._env):
            if name in scope:
                return scope[name]
        d = fresh_name('ptr')
        self.emit(IRAlloc(dest=d, type=IR_ANY))
        self._env[-1][name] = d
        return d

    def _expr_to_call(self, expr):
        from jocky_ast import CallExpr, MemberExpr, Identifier
        if isinstance(expr, CallExpr):
            if isinstance(expr.callee, Identifier):
                return expr.callee.name, [self._build_expr(a) for a in expr.args]
            if isinstance(expr.callee, MemberExpr):
                return self._member_path(expr.callee), \
                       [self._build_expr(a) for a in expr.args]
        return str(expr), []

    # ── emission helpers ──────────────────────────────────────────────────────

    def emit(self, instr: IRInstr):
        if self.cur_bb is not None:
            self.cur_bb.append(instr)

    def _new_block(self, label: str) -> BasicBlock:
        bb = BasicBlock(label=label)
        if self.cur_fn:
            self.cur_fn.blocks.append(bb)
        self.cur_bb = bb
        return bb
