# jocky_ast.py — JOCKY Language AST Node Definitions
# Every node in the JOCKY AST is a typed dataclass.
# The parser produces these; the semantic analyser annotates them;
# the IR emitter consumes them.

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Any


# ─────────────────────────────────────────────────────────────────────────────
# BASE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ASTNode:
    line: int = 0
    col:  int = 0
    # Semantic analysis fills this in
    inferred_type: Optional[str] = field(default=None, compare=False, repr=False)


# ─────────────────────────────────────────────────────────────────────────────
# TYPE REFERENCES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TypeRef(ASTNode):
    """A reference to a JOCKY type in source code."""
    name: str = ""          # e.g. "int", "string", "MyStruct"


@dataclass
class ArrayTypeRef(ASTNode):
    size: Optional[ASTNode] = None   # None → slice
    element: Optional[TypeRef] = None


@dataclass
class MapTypeRef(ASTNode):
    key:   Optional[TypeRef] = None
    value: Optional[TypeRef] = None


@dataclass
class PointerTypeRef(ASTNode):
    base: Optional[TypeRef] = None


@dataclass
class ChanTypeRef(ASTNode):
    element: Optional[TypeRef] = None


@dataclass
class FuncTypeRef(ASTNode):
    params:  List[TypeRef] = field(default_factory=list)
    returns: List[TypeRef] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# LITERALS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IntLiteral(ASTNode):
    value: int = 0

@dataclass
class FloatLiteral(ASTNode):
    value: float = 0.0

@dataclass
class StringLiteral(ASTNode):
    value: str = ""

@dataclass
class BoolLiteral(ASTNode):
    value: bool = False

@dataclass
class NilLiteral(ASTNode):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# EXPRESSIONS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Identifier(ASTNode):
    name: str = ""


@dataclass
class BinaryExpr(ASTNode):
    op:    str = ""
    left:  Optional[ASTNode] = None
    right: Optional[ASTNode] = None


@dataclass
class UnaryExpr(ASTNode):
    op:      str = ""
    operand: Optional[ASTNode] = None


@dataclass
class CallExpr(ASTNode):
    callee: Optional[ASTNode] = None
    args:   List[ASTNode] = field(default_factory=list)


@dataclass
class IndexExpr(ASTNode):
    obj:   Optional[ASTNode] = None
    index: Optional[ASTNode] = None


@dataclass
class MemberExpr(ASTNode):
    """obj.field or obj->field"""
    obj:    Optional[ASTNode] = None
    member: str = ""
    arrow:  bool = False   # True if ->


@dataclass
class SliceLiteral(ASTNode):
    elements: List[ASTNode] = field(default_factory=list)


@dataclass
class MapLiteral(ASTNode):
    pairs: List[tuple] = field(default_factory=list)   # list of (key_expr, val_expr)


@dataclass
class StructLiteral(ASTNode):
    type_name: str = ""
    fields:    List[tuple] = field(default_factory=list)  # list of (name, expr)


@dataclass
class FuncLiteral(ASTNode):
    """Anonymous function / closure."""
    params:  List[ParamDecl] = field(default_factory=list)
    returns: List[TypeRef]   = field(default_factory=list)
    body:    Optional[Block] = None
    captures: List[str]      = field(default_factory=list)  # filled by semantic


@dataclass
class TypeCast(ASTNode):
    target_type: str = ""
    expr: Optional[ASTNode] = None


@dataclass
class MakeExpr(ASTNode):
    """make(chan T, cap) or make([]T, len, cap)"""
    type_ref: Optional[ASTNode] = None
    args:     List[ASTNode] = field(default_factory=list)


@dataclass
class AppendExpr(ASTNode):
    slice_expr: Optional[ASTNode] = None
    value_expr: Optional[ASTNode] = None


# ─────────────────────────────────────────────────────────────────────────────
# STATEMENTS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Block(ASTNode):
    stmts: List[ASTNode] = field(default_factory=list)


@dataclass
class ExprStmt(ASTNode):
    expr: Optional[ASTNode] = None


@dataclass
class AssignStmt(ASTNode):
    """x = expr  or  x += expr  or  x, y = expr, expr"""
    targets: List[ASTNode] = field(default_factory=list)
    op:      str = "="
    values:  List[ASTNode] = field(default_factory=list)


@dataclass
class ShortAssignStmt(ASTNode):
    """x := expr  (declare + assign, type inferred)"""
    name:  str = ""
    value: Optional[ASTNode] = None


@dataclass
class VarDecl(ASTNode):
    name:     str = ""
    type_ref: Optional[ASTNode] = None
    value:    Optional[ASTNode] = None


@dataclass
class ConstDecl(ASTNode):
    name:     str = ""
    type_ref: Optional[ASTNode] = None
    value:    Optional[ASTNode] = None


@dataclass
class IfStmt(ASTNode):
    cond:      Optional[ASTNode] = None
    then_body: Optional[Block]   = None
    else_body: Optional[ASTNode] = None   # Block or IfStmt


@dataclass
class ForStmt(ASTNode):
    """for cond { } or infinite for { }"""
    cond: Optional[ASTNode] = None
    body: Optional[Block]   = None


@dataclass
class ForInStmt(ASTNode):
    """for item in collection { }"""
    var:        str = ""
    iterable:   Optional[ASTNode] = None
    body:       Optional[Block]   = None


@dataclass
class WhileStmt(ASTNode):
    cond: Optional[ASTNode] = None
    body: Optional[Block]   = None


@dataclass
class ReturnStmt(ASTNode):
    values: List[ASTNode] = field(default_factory=list)


@dataclass
class BreakStmt(ASTNode):
    pass


@dataclass
class ContinueStmt(ASTNode):
    pass


@dataclass
class DeferStmt(ASTNode):
    expr: Optional[ASTNode] = None


@dataclass
class GoStmt(ASTNode):
    expr: Optional[ASTNode] = None


@dataclass
class UsingStmt(ASTNode):
    expr: Optional[ASTNode] = None
    body: Optional[Block]   = None


@dataclass
class MatchCase(ASTNode):
    pattern:     Optional[ASTNode] = None   # None → default
    body:        Optional[Block]   = None
    fallthrough: bool = False


@dataclass
class MatchStmt(ASTNode):
    subject: Optional[ASTNode] = None
    cases:   List[MatchCase]   = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# DECLARATIONS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParamDecl(ASTNode):
    name:     str = ""
    type_ref: Optional[ASTNode] = None
    variadic: bool = False


@dataclass
class FuncDecl(ASTNode):
    name:        str = ""
    params:      List[ParamDecl] = field(default_factory=list)
    returns:     List[TypeRef]   = field(default_factory=list)
    body:        Optional[Block] = None
    attributes:  List[str]       = field(default_factory=list)  # @polymorphic etc.
    is_exported: bool = False


@dataclass
class FieldDecl(ASTNode):
    name:     str = ""
    type_ref: Optional[ASTNode] = None


@dataclass
class StructDecl(ASTNode):
    name:   str = ""
    fields: List[FieldDecl] = field(default_factory=list)


@dataclass
class MethodSig(ASTNode):
    name:    str = ""
    params:  List[ParamDecl] = field(default_factory=list)
    returns: List[TypeRef]   = field(default_factory=list)


@dataclass
class InterfaceDecl(ASTNode):
    name:    str = ""
    methods: List[MethodSig] = field(default_factory=list)


@dataclass
class ImportDecl(ASTNode):
    path:  str = ""
    alias: str = ""     # optional alias


@dataclass
class ModuleDecl(ASTNode):
    name: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# TOP LEVEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Program(ASTNode):
    module:     Optional[ModuleDecl] = None
    imports:    List[ImportDecl]     = field(default_factory=list)
    structs:    List[StructDecl]     = field(default_factory=list)
    interfaces: List[InterfaceDecl]  = field(default_factory=list)
    functions:  List[FuncDecl]       = field(default_factory=list)
    globals:    List[ASTNode]        = field(default_factory=list)  # VarDecl, ConstDecl
