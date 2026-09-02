# jockyc.py — JOCKY Compiler CLI Driver
# Usage:
#   python jockyc.py [options] <source.jky>
#
# Options:
#   -target windows|linux|native     Target platform (default: native)
#   -output <file>                   Output file path
#   -obfuscate                       Enable polymorphic obfuscation (default: on)
#   -no-obfuscate                    Disable obfuscation
#   -debug                           Run in interpreter mode (tree-walk)
#   -emit-ir                         Dump JOCKY-IR to stdout and exit
#   -emit-llvm                       Dump LLVM IR to stdout and exit
#   -opt <0-3>                       Optimization level (default: 2)
#   -validate                        Validate source only, do not compile
#   -morph                           Apply polymorphic engine to source and print
#   -v                               Verbose output

import sys
import os
import argparse

# Make sure we can import from the interpreter package
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from jocky_lexer       import JockyLexer, LexerError
from jocky_parser      import JockyParser, ParseError
from jocky_ir          import IRBuilder
from jocky_interpreter import JockyInterpreter, validate_jocky_script
from polymorphic       import PolymorphicEngine
from llvm_compiler     import JockyCompiler


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
     ___  ___   ___ _  _____   __
    |_ _|/ _ \ / __| |/ /\ \ / /
     | || (_) | (__| ' <  \ V /
    |___|\___/ \___|_|\_\  |_|

    JOCKY Forensic Language Compiler v1.0
    Cross-platform | Polymorphic | In-memory
"""


# ─────────────────────────────────────────────────────────────────────────────
# COLOURS  (ANSI, disabled on Windows without VT100)
# ─────────────────────────────────────────────────────────────────────────────

try:
    import colorama
    colorama.init()
    _COLOR = True
except ImportError:
    _COLOR = False


def _c(code: str, text: str) -> str:
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(msg):   print(_c("92", f"  [OK] {msg}"))
def err(msg):  print(_c("91", f"  [ERR] {msg}"), file=sys.stderr)
def info(msg): print(_c("36", f"  [>>] {msg}"))
def warn(msg): print(_c("93", f"  [!!] {msg}"))


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jockyc",
        description="JOCKY Forensic Language Compiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jockyc.py forensics.jky
  python jockyc.py -debug forensics.jky
  python jockyc.py -emit-ir forensics.jky
  python jockyc.py -target windows -output out.o forensics.jky
  python jockyc.py -morph forensics.jky
  python jockyc.py -validate forensics.jky
""")
    p.add_argument("source", help="JOCKY source file (.jky)")
    p.add_argument("-target",       default="native",
                   choices=["native", "windows", "linux"],
                   help="Compilation target (default: native)")
    p.add_argument("-output", "-o", default=None,
                   metavar="FILE", help="Output file path")
    p.add_argument("-obfuscate",    action="store_true", default=True,
                   help="Enable polymorphic obfuscation (default: on)")
    p.add_argument("-no-obfuscate", action="store_true", default=False,
                   dest="no_obfuscate",
                   help="Disable obfuscation")
    p.add_argument("-cfg-alter",    action="store_true", default=True,
                   help="Enable explicit LLVM CFG alteration passes (default: on)")
    p.add_argument("-no-cfg-alter", action="store_true", default=False,
                   dest="no_cfg_alter",
                   help="Disable explicit LLVM CFG alteration passes")
    p.add_argument("-debug",        action="store_true", default=False,
                   help="Run in interpreter mode (no compilation)")
    p.add_argument("-emit-ir",      action="store_true", default=False,
                   dest="emit_ir",
                   help="Dump JOCKY-IR and exit")
    p.add_argument("-emit-llvm",    action="store_true", default=False,
                   dest="emit_llvm",
                   help="Dump LLVM IR and exit")
    p.add_argument("-opt",          type=int, default=2,
                   choices=[0, 1, 2, 3],
                   metavar="LEVEL",
                   help="Optimization level 0-3 (default: 2)")
    p.add_argument("-validate",     action="store_true", default=False,
                   help="Validate source only, do not compile or run")
    p.add_argument("-morph",        action="store_true", default=False,
                   help="Apply polymorphic engine to source and print")
    p.add_argument("-v",            action="store_true", default=False,
                   dest="verbose",
                   help="Verbose output")
    return p


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def cmd_validate(source: str) -> bool:
    result = validate_jocky_script(source)
    if result["valid"]:
        ok(f"Source is valid")
        ok(f"Tokens:    {result.get('tokens', '?')}")
        ok(f"AST nodes: {result.get('ast_nodes', '?')}")
        ok(f"Functions: {result.get('functions', '?')}")
        ok(f"Imports:   {result.get('imports', '?')}")
        ok(f"Structs:   {result.get('structs', '?')}")
        return True
    else:
        for e in result["errors"]:
            err(e)
        return False


def cmd_emit_ir(source: str):
    lexer   = JockyLexer()
    tokens  = lexer.tokenize(source)
    parser  = JockyParser(tokens)
    ast     = parser.parse()
    builder = IRBuilder()
    ir_mod  = builder.build(ast)
    print(ir_mod.dump())


def cmd_emit_llvm(source: str, opt: int, target: str, obfuscate: bool, cfg_alter: bool = True):
    compiler = JockyCompiler(obfuscate=obfuscate)
    result   = compiler.compile(source, optimization_level=opt, target=target, cfg_alter=cfg_alter)
    print(result["llvm_ir"])


def cmd_debug(source: str, verbose: bool):
    interp = JockyInterpreter(verbose=verbose)
    interp.exec_source(source)
    interp.wait_goroutines()


def cmd_morph(source: str):
    engine = PolymorphicEngine()
    result = engine.morph(source)
    print("=" * 65)
    print(f"Build hash  : {result.build_hash}")
    print(f"XOR key     : 0x{result.encryption_key:02X}")
    print(f"Nonce       : {result.nonce}")
    print("\nTransformation log:")
    for entry in result.transformation_log:
        print(f"  {entry}")
    print("\n" + "─" * 65)
    print("Morphed source:")
    print("─" * 65)
    print(result.morphed_code)


def cmd_compile(source: str, opt: int, target: str, obfuscate: bool,
                output: str, verbose: bool, cfg_alter: bool = True):
    compiler = JockyCompiler(obfuscate=obfuscate)
    info(f"Compiling -> target={target}  opt={opt}  obfuscate={obfuscate}  cfg_alter={cfg_alter}")

    result = compiler.compile(source, output_file=output,
                               optimization_level=opt, target=target,
                               cfg_alter=cfg_alter)

    ok(f"Build ID    : {result['build_id']}")
    ok(f"Build hash  : {result['build_hash'][:32]}...")
    ok(f"Object size : {result['object_size']}")
    ok(f"Functions   : {result['ast_functions']}")
    if result.get("cfg_passes"):
        ok(f"CFG Passes  : {len(result['cfg_passes'])} transformation passes applied")
    if result.get("morph_nonce"):
        ok(f"Morph nonce : {result['morph_nonce']}")
    if result.get("note"):
        warn(result["note"])
    if verbose:
        if result.get("cfg_passes"):
            print("\n-- LLVM CFG Transformation Pipeline --")
            for p in result["cfg_passes"]:
                print(f"  [+] {p}")
        print("\n-- JOCKY-IR Preview --")
        for line in result["jocky_ir"].split('\n')[:30]:
            print(f"  {line}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = build_arg_parser()
    args   = parser.parse_args()

    # Read source file
    src_path = args.source
    if not os.path.isfile(src_path):
        err(f"File not found: {src_path!r}")
        sys.exit(1)

    with open(src_path, 'r', encoding='utf-8') as f:
        source = f.read()

    info(f"Source: {src_path}  ({len(source)} bytes, "
         f"{source.count(chr(10))+1} lines)")

    obfuscate = not args.no_obfuscate
    cfg_alter = not args.no_cfg_alter

    try:
        # ── Mode selection ───────────────────────────────────────────────────
        if args.validate:
            ok("Running validation...")
            success = cmd_validate(source)
            sys.exit(0 if success else 1)

        if args.morph:
            cmd_morph(source)
            sys.exit(0)

        if args.emit_ir:
            cmd_emit_ir(source)
            sys.exit(0)

        if args.emit_llvm:
            cmd_emit_llvm(source, args.opt, args.target, obfuscate, cfg_alter)
            sys.exit(0)

        if args.debug:
            info("Running in interpreter mode...")
            cmd_debug(source, args.verbose)
            sys.exit(0)

        # Default: compile
        cmd_compile(source, args.opt, args.target, obfuscate,
                    args.output, args.verbose, cfg_alter)


    except (LexerError, ParseError) as e:
        err(f"Syntax error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        warn("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        err(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
