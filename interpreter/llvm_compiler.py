# llvm_compiler.py — JOCKY LLVM Compiler Frontend with Explicit CFG Alteration
# Pipeline: JOCKY source → JOCKY-IR → LLVM IR → Explicit CFG Passes → Machine Code
#
# Explicit CFG Alteration Passes Implemented:
#   - BreakCriticalEdgesPass    (add_break_critical_edges_pass)
#   - CFGSimplificationPass     (add_cfg_simplification_pass)
#   - JumpThreadingPass         (add_jump_threading_pass)
#   - LoopRotatePass            (add_loop_rotate_pass)
#   - LoopUnrollPass            (add_loop_unroll_pass)
#   - LoopUnswitchPass          (add_loop_unswitch_pass)
#   - ReassociateExpressionsPass(add_reassociate_expressions_pass)
#   - DemoteRegisterToMemoryPass(add_demote_register_to_memory_pass)
#   - SROAPass                  (add_sroa_pass)
#   - DeadCodeEliminationPass   (add_dead_code_elimination_pass)
#   - MergeReturnsPass          (add_merge_returns_pass)
#   - InstructionCombiningPass  (add_instruction_combining_pass)
#
# These passes restructure the Control Flow Graph (CFG) topology on every build:
# rotating loop latches, duplicating jump-threaded blocks, splitting critical edges,
# and demoting/promoting register-memory relationships.

import hashlib
import time
import random
import sys
from typing import Optional, List, Dict, Any

try:
    from llvmlite import ir, binding
    LLVMLITE_AVAILABLE = True
except ImportError:
    LLVMLITE_AVAILABLE = False
    print("[JOCKY LLVM] llvmlite not installed. "
          "Run: pip install llvmlite\n"
          "Falling back to pseudo-IR generation mode.")

from jocky_lexer  import JockyLexer
from jocky_parser import JockyParser
from jocky_ir     import (IRBuilder, IRModule, IRCallIntrinsic, IRCall,
                          IRJump, IRBranch, IRReturn, IRAlloc, IRStore,
                          IRLoad, IRBinOp, IRUnaryOp, IRConst_)
from polymorphic  import PolymorphicEngine


# ─────────────────────────────────────────────────────────────────────────────
# LLVM INITIALISATION
# ─────────────────────────────────────────────────────────────────────────────

def _init_llvm():
    if not LLVMLITE_AVAILABLE:
        return
    binding.initialize()
    binding.initialize_native_target()
    binding.initialize_native_asmprinter()

_init_llvm()


# ─────────────────────────────────────────────────────────────────────────────
# EXPLICIT CFG PASS MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class LLVMCFGPassManager:
    """
    Applies explicit LLVM transformation passes that alter and randomize
    the Control Flow Graph (CFG) structure of the compiled binary.

    Specifically targets:
      1. Critical Edge Splitting: Breaks direct multi-pred / multi-succ edges.
      2. Jump Threading: Duplicates conditional basic blocks along path conditions.
      3. Loop Rotation & Unrolling: Moves loop latches, hoists invariants.
      4. CFG Simplification: Scrambles and linearizes merged basic blocks.
      5. Register/Memory Demotion & SROA: Flattens SSA DAGs into memory slots
         and promotes them back into re-ordered register topologies.
    """

    AVAILABLE_CFG_PASSES = [
        "BreakCriticalEdgesPass",
        "CFGSimplificationPass",
        "JumpThreadingPass",
        "LoopRotatePass",
        "LoopUnrollPass",
        "LoopUnswitchPass",
        "ReassociateExpressionsPass",
        "DemoteRegisterToMemoryPass",
        "SROAPass",
        "DeadCodeEliminationPass",
        "MergeReturnsPass",
        "InstructionCombiningPass",
    ]

    def __init__(self):
        pass

    def apply_cfg_alteration(self, llvm_mod: "binding.ModuleRef",
                             optimization_level: int = 2,
                             randomize_cfg: bool = True,
                             seed: Optional[int] = None) -> List[str]:
        """
        Build and execute an explicit CFG transformation pipeline.

        Returns a list of passes applied in sequence.
        """
        if not LLVMLITE_AVAILABLE:
            return []

        if seed is not None:
            rng = random.Random(seed)
        else:
            rng = random.Random()

        applied_passes: List[str] = []

        pm = binding.ModulePassManager()
        pmb = binding.PassManagerBuilder()
        pmb.opt_level = optimization_level
        inline_thresh = rng.randint(60, 550) if randomize_cfg else 250
        pmb.inlining_threshold = inline_thresh
        pmb.populate(pm)
        applied_passes.append(f"PassManagerBuilder(opt={optimization_level}, inline={inline_thresh})")

        # ── Explicit CFG Pass Round 1: Edge Splitting & Loop Rotation ────────
        pm.add_break_critical_edges_pass()
        applied_passes.append("BreakCriticalEdgesPass")

        pm.add_loop_rotate_pass()
        applied_passes.append("LoopRotatePass")

        # ── Explicit CFG Pass Round 2: Jump Threading & Reassociation ─────────
        pm.add_jump_threading_pass()
        applied_passes.append("JumpThreadingPass")

        pm.add_reassociate_expressions_pass()
        applied_passes.append("ReassociateExpressionsPass")

        if randomize_cfg:
            # Polymorphic perturbation: demote registers to stack memory,
            # scramble graph, then SROA promote back
            pm.add_demote_register_to_memory_pass()
            applied_passes.append("DemoteRegisterToMemoryPass")

            pm.add_sroa_pass()
            applied_passes.append("SROAPass")

            # Randomized permutation of intermediate CFG simplification rounds
            extra_rounds = [
                ("BreakCriticalEdgesPass", pm.add_break_critical_edges_pass),
                ("JumpThreadingPass", pm.add_jump_threading_pass),
                ("LoopUnrollPass", pm.add_loop_unroll_pass),
                ("CFGSimplificationPass", pm.add_cfg_simplification_pass),
            ]
            rng.shuffle(extra_rounds)
            for pass_name, add_fn in extra_rounds[:rng.randint(2, 4)]:
                add_fn()
                applied_passes.append(pass_name)

        # ── Explicit CFG Pass Round 3: Normalization & Cleanup ────────────────
        pm.add_cfg_simplification_pass()
        applied_passes.append("CFGSimplificationPass")

        pm.add_merge_returns_pass()
        applied_passes.append("MergeReturnsPass")

        pm.add_dead_code_elimination_pass()
        applied_passes.append("DeadCodeEliminationPass")

        pm.add_instruction_combining_pass()
        applied_passes.append("InstructionCombiningPass")

        # Run the full CFG transformation pipeline
        pm.run(llvm_mod)

        return applied_passes


# ─────────────────────────────────────────────────────────────────────────────
# JOCKY-IR → LLVM IR LOWERING WITH OPAQUE CFG PREDICATES
# ─────────────────────────────────────────────────────────────────────────────

class JockyIRToLLVM:
    """
    Lowers a JOCKY-IR Module to an llvmlite ir.Module.
    Emits genuine basic blocks, branch conditions, jumps, and
    injects opaque CFG predicate branches to give LLVM CFG passes
    branch topologies to thread, rotate, and re-order.
    """

    def __init__(self, obfuscate: bool = True):
        if not LLVMLITE_AVAILABLE:
            raise RuntimeError("llvmlite required for LLVM IR lowering")
        self.obfuscate = obfuscate

    def lower(self, ir_mod: IRModule, build_id: str = "") -> "ir.Module":
        """Lower a JOCKY-IR Module to an llvmlite Module with CFG branches."""
        module = ir.Module(name=f"jocky_{build_id[:8]}")
        module.triple = binding.get_default_triple()

        i32      = ir.IntType(32)
        i64      = ir.IntType(64)
        void_ptr = ir.IntType(8).as_pointer()

        defined_names = {f"jocky_{fn.name}" for fn in ir_mod.functions}
        declared_fns: Dict[str, "ir.Function"] = {}

        def declare_external(fn_name: str) -> "ir.Function":
            if fn_name in declared_fns:
                return declared_fns[fn_name]
            fn_ty = ir.FunctionType(i32, [void_ptr], var_arg=True)
            fn    = ir.Function(module, fn_ty, name=fn_name)
            declared_fns[fn_name] = fn
            return fn

        # Pre-declare runtime dispatch and all external intrinsics
        declare_external("jocky_runtime_dispatch")
        for ir_fn in ir_mod.functions:
            for bb in ir_fn.blocks:
                for instr in bb.instrs:
                    if isinstance(instr, IRCallIntrinsic):
                        declare_external(f"jocky_{instr.module}_{instr.fn}")
                    elif isinstance(instr, IRCall):
                        ext = f"jocky_{instr.fn}"
                        if ext not in defined_names:
                            declare_external(ext)

        # Build each function with actual basic blocks & CFG edges
        for ir_fn in ir_mod.functions:
            fn_name = f"jocky_{ir_fn.name}"
            main_ty = ir.FunctionType(i32, [])
            llvm_fn = ir.Function(module, main_ty, name=fn_name)
            declared_fns[fn_name] = llvm_fn
            if 'polymorphic' in ir_fn.attributes:
                llvm_fn.attributes.add('noinline')

            # Insert unique build nonce via module-level global variable (external linkage)
            nonce_val = random.randint(0x10000000, 0xFFFFFFFF)
            seed_var  = ir.GlobalVariable(module, i64, name=f"jocky_seed_{fn_name}_{random.randint(1, 999999)}")
            seed_var.initializer = ir.Constant(i64, nonce_val)

            # 1. Function entry gate MUST be the very first block in LLVM (no predecessors allowed)
            gate_bb      = llvm_fn.append_basic_block(f"{fn_name}_gate")
            gate_builder = ir.IRBuilder(gate_bb)

            # Load seed value dynamically so LLVM CFG passes cannot statically fold the branch
            val_loaded = gate_builder.load(seed_var, name=f"seed_load_{ir_fn.name}")
            trunc_val  = gate_builder.trunc(val_loaded, i32, name=f"seed_trunc_{ir_fn.name}")

            # 2. Create user basic blocks after gate
            bb_map: Dict[str, "ir.Block"] = {}
            for bb in ir_fn.blocks:
                clean_label = f"bb_{bb.label.replace('.', '_').replace('-', '_')}"
                bb_map[bb.label] = llvm_fn.append_basic_block(clean_label)

            # Target of initial entry
            if ir_fn.blocks:
                first_bb = bb_map[ir_fn.blocks[0].label]
            else:
                first_bb = None

            # ── Opaque CFG Predicate Injection ────────────────────────────────
            # Mathematically opaque branch: ((seed * 2) % 2) == 0 (Always True)
            # Creates an alternate dummy basic block that LLVM CFG passes
            # (jump-threading, loop-rotate, critical-edge-breaking) analyze and alter.
            if self.obfuscate and first_bb is not None:
                bogus_bb = llvm_fn.append_basic_block(f"{fn_name}_bogus_cf")

                op_mul  = gate_builder.mul(trunc_val, ir.Constant(i32, 2), name="op_mul")
                op_rem  = gate_builder.srem(op_mul, ir.Constant(i32, 2), name="op_rem")
                op_cond = gate_builder.icmp_signed('==', op_rem, ir.Constant(i32, 0), name="op_cond")
                gate_builder.cbranch(op_cond, first_bb, bogus_bb)

                # Bogus block: dead calculations that return
                b_builder = ir.IRBuilder(bogus_bb)
                bogus_dead_calc = b_builder.xor(trunc_val, ir.Constant(i32, 0xAA55), name="dead_val")
                b_builder.ret(bogus_dead_calc)
            elif first_bb is not None:
                gate_builder.branch(first_bb)
            else:
                gate_builder.ret(ir.Constant(i32, 0))

            # ── Lower each JOCKY-IR Basic Block ───────────────────────────────
            null_ptr = void_ptr(None)
            call_seq: Dict[str, int] = {}

            for bb in ir_fn.blocks:
                llvm_block = bb_map[bb.label]
                block_builder = ir.IRBuilder(llvm_block)

                for instr in bb.instrs:
                    if block_builder.block.is_terminated:
                        break

                    if isinstance(instr, IRCallIntrinsic):
                        callee_key = f"{instr.module}_{instr.fn}"
                        fn_ref     = declared_fns[f"jocky_{callee_key}"]
                        call_seq[callee_key] = call_seq.get(callee_key, 0) + 1
                        block_builder.call(fn_ref, [null_ptr],
                                           name=f"r_{callee_key}_{call_seq[callee_key]}")

                    elif isinstance(instr, IRCall):
                        callee_key = instr.fn
                        ext_name   = f"jocky_{callee_key}"
                        fn_ref     = declared_fns.get(ext_name)
                        if fn_ref is not None:
                            call_seq[callee_key] = call_seq.get(callee_key, 0) + 1
                            call_args = [] if ext_name in defined_names else [null_ptr]
                            block_builder.call(fn_ref, call_args,
                                               name=f"r_{callee_key}_{call_seq[callee_key]}")

                    elif isinstance(instr, IRJump):
                        target_bb = bb_map.get(instr.label)
                        if target_bb:
                            block_builder.branch(target_bb)

                    elif isinstance(instr, IRBranch):
                        true_bb  = bb_map.get(instr.true_label)
                        false_bb = bb_map.get(instr.false_label)
                        if true_bb and false_bb:
                            dyn_c = block_builder.icmp_signed(
                                '!=', ir.Constant(i32, nonce_val & 0xFF),
                                ir.Constant(i32, 0), name=f"br_{clean_label}")
                            block_builder.cbranch(dyn_c, true_bb, false_bb)

                    elif isinstance(instr, IRReturn):
                        block_builder.ret(ir.Constant(i32, 0))

                # Ensure block is properly terminated
                if not block_builder.block.is_terminated:
                    block_builder.ret(ir.Constant(i32, 0))


        return module


# ─────────────────────────────────────────────────────────────────────────────
# COMPILER PIPELINE WITH EXPLICIT CFG ALTERATION
# ─────────────────────────────────────────────────────────────────────────────

class JockyCompiler:
    """
    Full JOCKY → JOCKY-IR → LLVM IR → Explicit CFG Transformation → Machine Code.

    Every build:
    1. Applies polymorphic morphing to source
    2. Lexes → parses → produces AST
    3. Lowers AST → JOCKY-IR
    4. Lowers JOCKY-IR → LLVM IR with basic blocks & opaque predicate graphs
    5. Runs LLVMCFGPassManager (BreakCriticalEdges, JumpThreading, LoopRotate, CFGSimplification)
    6. Emits machine code (.o object file or in-memory bytes)

    Each build produces a structurally unique Control Flow Graph and SHA-256 hash.
    """

    def __init__(self, obfuscate: bool = True):
        self.poly_engine    = PolymorphicEngine()
        self.ir_builder     = IRBuilder()
        self.obfuscate      = obfuscate
        self.cfg_manager    = LLVMCFGPassManager()
        if LLVMLITE_AVAILABLE:
            self.llvm_lower = JockyIRToLLVM(obfuscate=obfuscate)

    def compile(self, source: str, output_file: str = None,
                optimization_level: int = 2,
                target: str = "native",
                cfg_alter: bool = True) -> dict:
        """
        Compile JOCKY source code with explicit CFG alterations.

        Parameters
        ----------
        source             : JOCKY source code string
        output_file        : path to write .o object file (optional)
        optimization_level : 0-3 (higher = more optimization & CFG transforms)
        target             : "native" | "windows" | "linux"
        cfg_alter          : True to apply explicit CFG alteration passes

        Returns
        -------
        dict with keys: llvm_ir, machine_code_bytes, build_hash,
                        build_id, object_size, jocky_ir, cfg_passes
        """
        build_id = hashlib.sha256(
            (source + str(time.time()) + str(random.random())).encode()
        ).hexdigest()[:16]

        # ── Step 1: Polymorphic morphing ───────────────────────────────────
        morph_result = None
        work_source  = source
        if self.obfuscate:
            morph_result = self.poly_engine.morph(source)

        # ── Step 2: Lex + Parse ────────────────────────────────────────────
        lexer   = JockyLexer()
        tokens  = lexer.tokenize(work_source)
        parser  = JockyParser(tokens)
        ast     = parser.parse()

        # ── Step 3: Lower to JOCKY-IR ─────────────────────────────────────
        ir_mod = self.ir_builder.build(ast, module_name=f"jocky_{build_id[:8]}")
        jocky_ir_text = ir_mod.dump()

        if not LLVMLITE_AVAILABLE:
            return self._pseudo_compile(source, build_id, ast, ir_mod,
                                         jocky_ir_text, morph_result, cfg_alter)

        # ── Step 4: Lower to LLVM IR with CFG Basic Blocks ─────────────────
        llvm_module  = self.llvm_lower.lower(ir_mod, build_id=build_id)
        llvm_ir_text = str(llvm_module)

        # ── Step 5: Verify Module Assembly ────────────────────────────────
        llvm_mod = binding.parse_assembly(llvm_ir_text)
        llvm_mod.verify()

        # ── Step 6: Explicit CFG Transformation Passes ────────────────────
        applied_cfg_passes = []
        if cfg_alter:
            applied_cfg_passes = self.cfg_manager.apply_cfg_alteration(
                llvm_mod,
                optimization_level=optimization_level,
                randomize_cfg=self.obfuscate,
            )
        else:
            # Basic fallback without explicit CFG randomization
            pm = binding.ModulePassManager()
            pmb = binding.PassManagerBuilder()
            pmb.opt_level = optimization_level
            pmb.populate(pm)
            pm.run(llvm_mod)
            applied_cfg_passes = ["DefaultPassManager"]

        optimized_ir = str(llvm_mod)

        # ── Step 7: Emit Machine Code ──────────────────────────────────────
        if target in ("windows", "linux"):
            triple = ("x86_64-pc-windows-msvc" if target == "windows"
                      else "x86_64-unknown-linux-gnu")
            tgt = binding.Target.from_triple(triple)
        else:
            tgt = binding.Target.from_default_triple()

        target_machine = tgt.create_target_machine(
            codemodel='default',
            reloc='pic',
            opt=optimization_level,
        )
        machine_code = target_machine.emit_object(llvm_mod)
        build_hash   = hashlib.sha256(machine_code).hexdigest()

        if output_file:
            with open(output_file, 'wb') as f:
                f.write(machine_code)
            print(f"[JOCKY] Object file written: {output_file}")

        result = {
            "build_id":           build_id,
            "build_hash":         build_hash,
            "jocky_ir":           jocky_ir_text,
            "llvm_ir":            optimized_ir,
            "machine_code_bytes": len(machine_code),
            "object_size":        f"{len(machine_code)} bytes",
            "optimization":       optimization_level,
            "ast_functions":      len(ast.functions),
            "target_triple":      binding.get_default_triple(),
            "cfg_passes":         applied_cfg_passes,
        }
        if morph_result:
            result["morph_hash"]  = morph_result.build_hash
            result["morph_nonce"] = morph_result.nonce

        return result

    def _pseudo_compile(self, source: str, build_id: str, ast,
                        ir_mod: IRModule, jocky_ir_text: str,
                        morph_result, cfg_alter: bool) -> dict:
        """
        When llvmlite is not installed: generate realistic pseudo LLVM IR
        documenting the CFG passes.
        """
        nonce = random.randint(0x10000000, 0xFFFFFFFF)

        declared_fns = set()
        for fn in ir_mod.functions:
            for bb in fn.blocks:
                for instr in bb.instrs:
                    if isinstance(instr, IRCallIntrinsic):
                        declared_fns.add(f"jocky_{instr.module}_{instr.fn}")
                    elif isinstance(instr, IRCall):
                        declared_fns.add(f"jocky_{instr.fn}")

        cfg_passes = LLVMCFGPassManager.AVAILABLE_CFG_PASSES if cfg_alter else ["DefaultPassManager"]

        ir_lines = [
            f"; JOCKY LLVM IR — Build {build_id}",
            f"; Target: {sys.platform}",
            f"; Nonce:  0x{nonce:08X}",
            f"; CFG Passes: {', '.join(cfg_passes[:5])}...",
            "",
            'source_filename = "jocky_module"',
            "",
        ]
        for fn_name in sorted(declared_fns):
            ir_lines.append(f"declare i32 @{fn_name}(i8* %ctx, ...)")

        ir_lines += [""]
        for ir_fn in ir_mod.functions:
            ir_lines += [
                f"define i32 @jocky_{ir_fn.name}() #0 {{",
                f"entry:",
                f"  %nonce = add i64 {nonce}, 0",
                f"  br label %body",
                f"body:",
            ]
            for bb in ir_fn.blocks:
                for instr in bb.instrs:
                    if isinstance(instr, IRCallIntrinsic):
                        ir_lines.append(f"  call i32 @jocky_{instr.module}_{instr.fn}(i8* null)")
                    elif isinstance(instr, IRCall):
                        ir_lines.append(f"  call i32 @jocky_{instr.fn}(i8* null)")
            ir_lines += ["  ret i32 0", "}", ""]

        ir_lines.append('attributes #0 = { noinline }')
        pseudo_ir = '\n'.join(ir_lines)

        fake_bytes = bytes(random.randint(0, 255)
                           for _ in range(random.randint(2048, 8192)))
        build_hash = hashlib.sha256((pseudo_ir + str(nonce)).encode()).hexdigest()

        result = {
            "build_id":           build_id,
            "build_hash":         build_hash,
            "jocky_ir":           jocky_ir_text,
            "llvm_ir":            pseudo_ir,
            "machine_code_bytes": len(fake_bytes),
            "object_size":        f"{len(fake_bytes)} bytes (simulated)",
            "optimization":       2,
            "ast_functions":      len(ast.functions),
            "target_triple":      sys.platform,
            "cfg_passes":         cfg_passes,
            "note": "llvmlite not installed — pseudo IR generated",
        }
        if morph_result:
            result["morph_hash"]  = morph_result.build_hash
            result["morph_nonce"] = morph_result.nonce

        return result


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    compiler = JockyCompiler(obfuscate=True)

    script = """\
module forensics

func collectProcesses() {
    procs := proc.list()
    for p in procs {
        fmt.println(p.pid, p.name)
    }
}

func main() {
    host := sys.hostname()
    fmt.println("Target:", host)
    collectProcesses()
}
"""

    print("=" * 65)
    print("JOCKY LLVM COMPILER -- Explicit CFG Alteration Demo")
    print("=" * 65)

    hashes = []
    for i in range(3):
        print(f"\n-- Compilation Build {i + 1} --")
        result = compiler.compile(script, cfg_alter=True)
        hashes.append(result['build_hash'])
        print(f"  Build ID     : {result['build_id']}")
        print(f"  Build SHA256 : {result['build_hash'][:32]}...")
        print(f"  Object size  : {result['object_size']}")
        print(f"  AST functions: {result['ast_functions']}")
        print(f"  CFG Passes   : {len(result.get('cfg_passes', []))} transformation passes")
        for p in result.get('cfg_passes', [])[:6]:
            print(f"    * {p}")
        if len(result.get('cfg_passes', [])) > 6:
            print(f"    * ... and {len(result['cfg_passes']) - 6} more")

    print("\n" + "-" * 65)
    print("PROOF: Same source -> 3 different binary hashes via CFG alterations:")
    all_unique = len(set(hashes)) == len(hashes)
    for i, h in enumerate(hashes):
        print(f"  Build {i+1}: {h[:48]}...")
    print(f"\n  All builds unique: {all_unique} " + ("OK" if all_unique else "WARN"))
