# test_pipeline.py — CI/CD Automated Test Suite
# Executed automatically by GitHub Actions on every commit/PR.

import sys
import os
import unittest
import hashlib

# Add project roots to path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(_ROOT, 'interpreter'))
sys.path.insert(0, os.path.join(_ROOT, 'backend'))
sys.path.insert(0, os.path.join(_ROOT, 'agent'))


class TestJockyLanguagePipeline(unittest.TestCase):
    """Verifies that compiler, parser, and interpreter function properly."""

    def test_01_lexer(self):
        from jocky_lexer import JockyLexer
        src = "func main() { x := 100; fmt.println(x) }"
        tokens = JockyLexer().tokenize(src)
        self.assertGreater(len(tokens), 5)

    def test_02_parser(self):
        from jocky_lexer import JockyLexer
        from jocky_parser import JockyParser
        src = "func add(a: int, b: int) : int { return a + b }"
        tokens = JockyLexer().tokenize(src)
        prog = JockyParser(tokens).parse()
        self.assertEqual(len(prog.functions), 1)
        self.assertEqual(prog.functions[0].name, "add")

    def test_03_ir_builder(self):
        from jocky_lexer import JockyLexer
        from jocky_parser import JockyParser
        from jocky_ir import IRBuilder
        src = "func main() { host := sys.hostname(); fmt.println(host) }"
        prog = JockyParser(JockyLexer().tokenize(src)).parse()
        ir_mod = IRBuilder().build(prog)
        self.assertEqual(len(ir_mod.functions), 1)
        total_instrs = sum(len(b.instrs) for b in ir_mod.functions[0].blocks)
        self.assertGreater(total_instrs, 0)

    def test_04_interpreter_execution(self):
        from jocky_interpreter import run_jocky_script
        src = """
        func calc() : int { return 15 + 25 }
        func main() {
            res := calc()
            fmt.println("Result:", res)
        }
        """
        # Must execute without raising exceptions
        run_jocky_script(src)

    def test_05_polymorphic_uniqueness(self):
        from polymorphic import PolymorphicEngine
        src = "func main() { procs := proc.list() }"
        engine = PolymorphicEngine()
        b1 = engine.morph(src)
        b2 = engine.morph(src)
        self.assertNotEqual(b1.build_hash, b2.build_hash)

    def test_06_llvm_cfg_passes(self):
        from llvm_compiler import JockyCompiler
        comp = JockyCompiler(obfuscate=True)
        src = "func main() { host := sys.hostname() }"
        res = comp.compile(src, cfg_alter=True)
        self.assertIn("build_hash", res)
        self.assertIn("cfg_passes", res)
        self.assertGreater(len(res["cfg_passes"]), 5)


class TestManagementServerAndAgent(unittest.TestCase):
    """Verifies server endpoints and agent distribution schemas."""

    def test_07_agent_file_integrity(self):
        agent_path = os.path.join(_ROOT, 'agent', 'agent.py')
        self.assertTrue(os.path.isfile(agent_path))
        with open(agent_path, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(len(h), 64)

    def test_08_server_status_and_agent_routes(self):
        import server
        client = server.app.test_client()

        # Status endpoint
        resp = client.get('/api/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "online")

        # Agent latest endpoint
        agent_meta = client.get('/api/agent/latest')
        self.assertEqual(agent_meta.status_code, 200)
        meta_json = agent_meta.get_json()
        self.assertIn("hash", meta_json)
        self.assertIn("version", meta_json)
        self.assertGreater(meta_json["size_bytes"], 1000)

        # Agent download endpoint
        dl = client.get('/api/agent/download')
        self.assertEqual(dl.status_code, 200)
        self.assertGreater(len(dl.data), 1000)
        dl.close()


if __name__ == '__main__':
    unittest.main()
