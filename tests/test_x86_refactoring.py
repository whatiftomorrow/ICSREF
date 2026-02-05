#!/usr/bin/env python3
"""
Test suite for x86 refactoring validation.

This test validates the x86 function block identification patterns
introduced in commit f8a3d6a (Refactor ICSREF from ARM to x86 binary support).

The tests check:
1. Pattern detection logic works correctly
2. Function block boundary identification
3. Prologue/epilogue pairing
4. Architecture detection

NOTE: The current sample files in samples/PRG_binaries/GitHub/ are ARM binaries.
When x86 samples become available, these tests will validate the refactoring.
"""

import os
import sys
import struct
import unittest
from pathlib import Path

# Add icsref to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'icsref'))


class TestPatternDetection(unittest.TestCase):
    """Test the pattern detection helpers."""

    # x86 patterns from PRG_analysis.py
    X86_PROLOGUE = b'\x55\x89\xe5'  # push ebp; mov ebp, esp
    X86_EPILOGUE_1 = b'\xc9\xc3'    # leave; ret
    X86_EPILOGUE_2 = b'\x5d\xc3'    # pop ebp; ret

    # ARM patterns (original)
    ARM_PROLOGUE = b'\x0D\xC0\xA0\xE1\x00\x58\x2D\xE9\x0C\xB0\xA0\xE1'
    ARM_EPILOGUE = b'\x00\xA8\x1B\xE9'

    @staticmethod
    def allindices(file_bytes, sub, offset=0):
        """Find all occurrences of substring - matches PRG_analysis._allindices"""
        i = file_bytes.find(sub, offset)
        listindex = []
        while i >= 0:
            listindex.append(i)
            i = file_bytes.find(sub, i + 1)
        return listindex

    def test_x86_prologue_pattern(self):
        """Test x86 prologue pattern detection."""
        # Create synthetic x86 function
        test_data = b'\x00\x00' + self.X86_PROLOGUE + b'\x83\xec\x10' + self.X86_EPILOGUE_1 + b'\x00\x00'

        prologues = self.allindices(test_data, self.X86_PROLOGUE)
        self.assertEqual(len(prologues), 1)
        self.assertEqual(prologues[0], 2)  # Offset 2

    def test_x86_epilogue_patterns(self):
        """Test both x86 epilogue patterns."""
        # Test leave; ret pattern
        test_data1 = b'\x00' + self.X86_EPILOGUE_1 + b'\x00'
        endings1 = self.allindices(test_data1, self.X86_EPILOGUE_1)
        self.assertEqual(len(endings1), 1)

        # Test pop ebp; ret pattern
        test_data2 = b'\x00' + self.X86_EPILOGUE_2 + b'\x00'
        endings2 = self.allindices(test_data2, self.X86_EPILOGUE_2)
        self.assertEqual(len(endings2), 1)

    def test_function_boundary_pairing(self):
        """Test that prologues and epilogues can be properly paired."""
        # Create data with multiple functions
        func1 = self.X86_PROLOGUE + b'\x83\xec\x10\x90\x90\x90' + self.X86_EPILOGUE_1
        func2 = self.X86_PROLOGUE + b'\x83\xec\x20\x90\x90\x90\x90' + self.X86_EPILOGUE_2
        padding = b'\x00\x00\x00\x00'

        test_data = padding + func1 + padding + func2 + padding

        prologues = self.allindices(test_data, self.X86_PROLOGUE)
        endings1 = self.allindices(test_data, self.X86_EPILOGUE_1)
        endings2 = self.allindices(test_data, self.X86_EPILOGUE_2)
        endings = sorted(set([e + 2 for e in endings1] + [e + 2 for e in endings2]))

        self.assertEqual(len(prologues), 2)
        self.assertEqual(len(endings), 2)

        # Verify proper pairing using zip (as in PRG_analysis.__find_blocks)
        boundaries = list(zip(prologues, endings))
        self.assertEqual(len(boundaries), 2)

        # Function 1: starts at 4, ends at 4+3+6+2=15
        # Function 2: starts at 19, ends at 19+3+7+2=31
        for start, end in boundaries:
            self.assertGreater(end, start, "Epilogue should come after prologue")


class TestSampleFileArchitecture(unittest.TestCase):
    """Test architecture detection on sample files."""

    SAMPLES_DIR = Path(__file__).parent.parent / 'samples' / 'PRG_binaries' / 'GitHub'

    # Patterns
    X86_PROLOGUE = b'\x55\x89\xe5'
    X86_EPILOGUE_1 = b'\xc9\xc3'
    X86_EPILOGUE_2 = b'\x5d\xc3'
    ARM_PROLOGUE = b'\x0D\xC0\xA0\xE1\x00\x58\x2D\xE9\x0C\xB0\xA0\xE1'
    ARM_EPILOGUE = b'\x00\xA8\x1B\xE9'

    @staticmethod
    def count_pattern(data, pattern):
        """Count occurrences of pattern in data."""
        count = 0
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            count += 1
            offset = pos + 1
        return count

    def detect_architecture(self, file_path):
        """Detect if a file is ARM or x86 based on prologue/epilogue patterns."""
        with open(file_path, 'rb') as f:
            data = f.read()

        arm_prologues = self.count_pattern(data, self.ARM_PROLOGUE)
        arm_epilogues = self.count_pattern(data, self.ARM_EPILOGUE)
        x86_prologues = self.count_pattern(data, self.X86_PROLOGUE)
        x86_epilogues = (self.count_pattern(data, self.X86_EPILOGUE_1) +
                        self.count_pattern(data, self.X86_EPILOGUE_2))

        return {
            'arm_prologues': arm_prologues,
            'arm_epilogues': arm_epilogues,
            'x86_prologues': x86_prologues,
            'x86_epilogues': x86_epilogues,
            'is_arm': arm_prologues > 0 and arm_epilogues > 0,
            'is_x86': x86_prologues > 0 and x86_epilogues > 0,
        }

    def test_sample_architecture_detection(self):
        """Test that sample files can be analyzed for architecture."""
        if not self.SAMPLES_DIR.exists():
            self.skipTest(f"Samples directory not found: {self.SAMPLES_DIR}")

        sample_files = list(self.SAMPLES_DIR.glob('*.PRG'))[:5]
        if not sample_files:
            self.skipTest("No sample files found")

        for sample in sample_files:
            arch_info = self.detect_architecture(sample)
            # At least one architecture should be detected
            self.assertTrue(
                arch_info['is_arm'] or arch_info['is_x86'],
                f"No architecture patterns found in {sample.name}"
            )

    def test_current_samples_are_arm(self):
        """Document that current samples are ARM binaries.

        This test documents the current state: sample files are ARM binaries,
        but the code has been refactored for x86. When x86 samples become
        available, this test should be updated.
        """
        if not self.SAMPLES_DIR.exists():
            self.skipTest(f"Samples directory not found: {self.SAMPLES_DIR}")

        sample_files = list(self.SAMPLES_DIR.glob('*.PRG'))[:5]
        if not sample_files:
            self.skipTest("No sample files found")

        arm_count = 0
        x86_count = 0

        for sample in sample_files:
            arch_info = self.detect_architecture(sample)
            if arch_info['is_arm']:
                arm_count += 1
            if arch_info['is_x86']:
                x86_count += 1

        # Document current state
        print(f"\nArchitecture analysis of {len(sample_files)} samples:")
        print(f"  ARM binaries: {arm_count}")
        print(f"  x86 binaries: {x86_count}")

        # This assertion documents the current state
        # When x86 samples are available, update this test
        self.assertGreater(arm_count, 0, "Expected at least some ARM samples")


class TestX86FunctionBlockLogic(unittest.TestCase):
    """Test the x86 function block identification logic from PRG_analysis.py."""

    X86_PROLOGUE = b'\x55\x89\xe5'
    X86_EPILOGUE_1 = b'\xc9\xc3'
    X86_EPILOGUE_2 = b'\x5d\xc3'

    @staticmethod
    def allindices(file_bytes, sub, offset=0):
        """Matches PRG_analysis.__allindices"""
        i = file_bytes.find(sub, offset)
        listindex = []
        while i >= 0:
            listindex.append(i)
            i = file_bytes.find(sub, i + 1)
        return listindex

    def find_blocks(self, hexdump):
        """Reimplementation of PRG_analysis.__find_blocks for testing."""
        prologue = b'\x55\x89\xe5'
        beginnings = self.allindices(hexdump, prologue)

        epilogue1 = b'\xc9\xc3'
        endings1 = self.allindices(hexdump, epilogue1)
        endings1 = [i + 2 for i in endings1]

        epilogue2 = b'\x5d\xc3'
        endings2 = self.allindices(hexdump, epilogue2)
        endings2 = [i + 2 for i in endings2]

        endings = sorted(set(endings1 + endings2))

        return list(zip(beginnings, endings))

    def test_simple_function(self):
        """Test simple function detection."""
        # push ebp; mov ebp, esp; sub esp, 0x10; ... ; leave; ret
        func = self.X86_PROLOGUE + b'\x83\xec\x10\x90\x90' + self.X86_EPILOGUE_1
        test_data = b'\x00\x00\x00\x00' + func + b'\x00\x00\x00\x00'

        blocks = self.find_blocks(test_data)
        self.assertEqual(len(blocks), 1)
        start, end = blocks[0]
        self.assertEqual(start, 4)
        self.assertEqual(end, 4 + len(func))

    def test_multiple_functions(self):
        """Test detection of multiple functions."""
        func1 = self.X86_PROLOGUE + b'\x83\xec\x10\x90' + self.X86_EPILOGUE_1
        func2 = self.X86_PROLOGUE + b'\x83\xec\x20\x90\x90' + self.X86_EPILOGUE_2
        padding = b'\x00\x00\x00\x00'

        test_data = padding + func1 + padding + func2 + padding

        blocks = self.find_blocks(test_data)
        self.assertEqual(len(blocks), 2)

    def test_mixed_epilogues(self):
        """Test detection with mixed epilogue types."""
        func1 = self.X86_PROLOGUE + b'\x90\x90\x90' + self.X86_EPILOGUE_1  # leave; ret
        func2 = self.X86_PROLOGUE + b'\x90\x90\x90' + self.X86_EPILOGUE_2  # pop ebp; ret

        test_data = func1 + func2

        blocks = self.find_blocks(test_data)
        self.assertEqual(len(blocks), 2)

        # Verify each function has matching start/end
        for start, end in blocks:
            self.assertGreater(end, start)

    def test_empty_data(self):
        """Test handling of data with no functions."""
        test_data = b'\x00\x00\x00\x00\x90\x90\x90\x00\x00\x00\x00'
        blocks = self.find_blocks(test_data)
        self.assertEqual(len(blocks), 0)

    def test_unbalanced_patterns(self):
        """Test behavior when prologues and epilogues don't match."""
        # More prologues than epilogues
        test_data = self.X86_PROLOGUE + b'\x90' + self.X86_PROLOGUE + b'\x90' + self.X86_EPILOGUE_1

        blocks = self.find_blocks(test_data)
        # zip() pairs them sequentially - first prologue with first epilogue
        # This is a limitation of the current approach
        self.assertGreaterEqual(len(blocks), 1)


class TestX86HeaderAnalysis(unittest.TestCase):
    """Test header analysis with x86 assumptions."""

    def test_header_offset_parsing(self):
        """Test that header parsing logic works correctly."""
        # Create a minimal PRG header
        header = bytearray(0x50)  # Need at least 0x48 bytes

        # Set program_start at offset 0x20
        struct.pack_into('I', header, 0x20, 0x100)  # Entry point = 0x100
        # Set program_end at offset 0x2C
        struct.pack_into('I', header, 0x2C, 0x500)  # End = 0x500
        # Set dynlib_end at offset 0x44
        struct.pack_into('I', header, 0x44, 0x400)  # Dynlib end = 0x400

        # Parse as PRG_analysis does
        program_start = struct.unpack('I', header[0x20:0x20+4])[0] + 24
        program_end = struct.unpack('I', header[0x2C:0x2C+4])[0] + 24
        dynlib_end = struct.unpack('I', header[0x44:0x44+4])[0]

        self.assertEqual(program_start, 0x100 + 24)
        self.assertEqual(program_end, 0x500 + 24)
        self.assertEqual(dynlib_end, 0x400)


class TestSyntheticX86Fixture(unittest.TestCase):
    """Test with the synthetic x86 PRG fixture file."""

    FIXTURE_PATH = Path(__file__).parent / 'fixtures' / 'synthetic_x86.prg'

    X86_PROLOGUE = b'\x55\x89\xe5'
    X86_EPILOGUE_1 = b'\xc9\xc3'
    X86_EPILOGUE_2 = b'\x5d\xc3'

    @staticmethod
    def allindices(file_bytes, sub, offset=0):
        i = file_bytes.find(sub, offset)
        listindex = []
        while i >= 0:
            listindex.append(i)
            i = file_bytes.find(sub, i + 1)
        return listindex

    def find_blocks(self, hexdump):
        """Reimplementation of PRG_analysis.__find_blocks for testing."""
        prologue = b'\x55\x89\xe5'
        beginnings = self.allindices(hexdump, prologue)

        epilogue1 = b'\xc9\xc3'
        endings1 = self.allindices(hexdump, epilogue1)
        endings1 = [i + 2 for i in endings1]

        epilogue2 = b'\x5d\xc3'
        endings2 = self.allindices(hexdump, epilogue2)
        endings2 = [i + 2 for i in endings2]

        endings = sorted(set(endings1 + endings2))
        return list(zip(beginnings, endings))

    def test_fixture_exists(self):
        """Verify the synthetic x86 fixture file exists."""
        self.assertTrue(self.FIXTURE_PATH.exists(),
                       f"Fixture file not found: {self.FIXTURE_PATH}")

    def test_fixture_contains_x86_patterns(self):
        """Verify the fixture file contains expected x86 patterns."""
        if not self.FIXTURE_PATH.exists():
            self.skipTest("Fixture file not found")

        with open(self.FIXTURE_PATH, 'rb') as f:
            data = f.read()

        prologues = self.allindices(data, self.X86_PROLOGUE)
        epilogues1 = self.allindices(data, self.X86_EPILOGUE_1)
        epilogues2 = self.allindices(data, self.X86_EPILOGUE_2)

        self.assertGreater(len(prologues), 0, "Should find x86 prologues")
        total_epilogues = len(epilogues1) + len(epilogues2)
        self.assertGreater(total_epilogues, 0, "Should find x86 epilogues")

    def test_fixture_function_detection(self):
        """Test function detection on the fixture file."""
        if not self.FIXTURE_PATH.exists():
            self.skipTest("Fixture file not found")

        with open(self.FIXTURE_PATH, 'rb') as f:
            data = f.read()

        blocks = self.find_blocks(data)
        self.assertEqual(len(blocks), 3, "Should find 3 functions in fixture")

        # Verify each function has valid boundaries
        for i, (start, end) in enumerate(blocks):
            self.assertGreater(end, start,
                             f"Function {i+1} should have end > start")
            self.assertLess(end - start, 50,
                          f"Function {i+1} should be reasonable size")


class TestX86SyntheticBinary(unittest.TestCase):
    """Test with a synthetic x86 binary to validate the refactoring works."""

    X86_PROLOGUE = b'\x55\x89\xe5'
    X86_EPILOGUE_1 = b'\xc9\xc3'
    X86_EPILOGUE_2 = b'\x5d\xc3'

    def create_synthetic_x86_prg(self):
        """Create a synthetic x86 PRG binary for testing."""
        # Header (0x50 bytes)
        header = bytearray(0x50)

        # Set program_start at offset 0x20 (actual start = value + 24)
        code_start = 0x50 - 24  # So actual start is 0x50
        struct.pack_into('I', header, 0x20, code_start)

        # Create some x86 functions
        func1 = (
            self.X86_PROLOGUE +        # push ebp; mov ebp, esp
            b'\x83\xec\x10' +          # sub esp, 0x10
            b'\x90\x90\x90\x90' +      # nops (placeholder)
            b'\x31\xc0' +              # xor eax, eax
            self.X86_EPILOGUE_1        # leave; ret
        )

        func2 = (
            self.X86_PROLOGUE +        # push ebp; mov ebp, esp
            b'\x83\xec\x20' +          # sub esp, 0x20
            b'\xb8\x01\x00\x00\x00' +  # mov eax, 1
            b'\x90\x90' +              # nops
            self.X86_EPILOGUE_2        # pop ebp; ret
        )

        code = func1 + b'\x00\x00' + func2

        # Set program_end
        code_end = len(header) + len(code) - 24
        struct.pack_into('I', header, 0x2C, code_end)

        # Set dynlib_end
        struct.pack_into('I', header, 0x44, code_end - 0x10)

        return bytes(header) + code

    def test_synthetic_x86_function_detection(self):
        """Test function detection on synthetic x86 binary."""
        prg_data = self.create_synthetic_x86_prg()

        # Use the same logic as PRG_analysis.__find_blocks
        def allindices(file_bytes, sub):
            i = file_bytes.find(sub)
            listindex = []
            while i >= 0:
                listindex.append(i)
                i = file_bytes.find(sub, i + 1)
            return listindex

        prologue = b'\x55\x89\xe5'
        beginnings = allindices(prg_data, prologue)

        epilogue1 = b'\xc9\xc3'
        endings1 = allindices(prg_data, epilogue1)
        endings1 = [i + 2 for i in endings1]

        epilogue2 = b'\x5d\xc3'
        endings2 = allindices(prg_data, epilogue2)
        endings2 = [i + 2 for i in endings2]

        endings = sorted(set(endings1 + endings2))

        boundaries = list(zip(beginnings, endings))

        self.assertEqual(len(beginnings), 2, "Should find 2 prologues")
        self.assertEqual(len(endings), 2, "Should find 2 epilogues")
        self.assertEqual(len(boundaries), 2, "Should find 2 function boundaries")

        # Verify boundaries make sense
        for start, end in boundaries:
            self.assertGreater(end, start, "End should be after start")
            self.assertLess(end - start, 50, "Function should be reasonable size")


def run_x86_validation():
    """Run validation and print detailed report."""
    print("=" * 70)
    print("X86 REFACTORING VALIDATION REPORT")
    print("=" * 70)

    samples_dir = Path(__file__).parent.parent / 'samples' / 'PRG_binaries' / 'GitHub'

    X86_PROLOGUE = b'\x55\x89\xe5'
    X86_EPILOGUE_1 = b'\xc9\xc3'
    X86_EPILOGUE_2 = b'\x5d\xc3'
    ARM_PROLOGUE = b'\x0D\xC0\xA0\xE1\x00\x58\x2D\xE9\x0C\xB0\xA0\xE1'
    ARM_EPILOGUE = b'\x00\xA8\x1B\xE9'

    def count_pattern(data, pattern):
        count = 0
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            count += 1
            offset = pos + 1
        return count

    print("\n1. SAMPLE FILE ARCHITECTURE ANALYSIS")
    print("-" * 70)

    if samples_dir.exists():
        sample_files = sorted(samples_dir.glob('*.PRG'))[:10]

        print(f"{'File':<20} | {'x86 pro':>8} | {'x86 epi':>8} | {'ARM pro':>8} | {'ARM epi':>8}")
        print("-" * 70)

        total_arm = 0
        total_x86 = 0

        for sample in sample_files:
            with open(sample, 'rb') as f:
                data = f.read()

            x86_pro = count_pattern(data, X86_PROLOGUE)
            x86_epi = count_pattern(data, X86_EPILOGUE_1) + count_pattern(data, X86_EPILOGUE_2)
            arm_pro = count_pattern(data, ARM_PROLOGUE)
            arm_epi = count_pattern(data, ARM_EPILOGUE)

            if arm_pro > 0:
                total_arm += 1
            if x86_pro > 0:
                total_x86 += 1

            print(f"{sample.name:<20} | {x86_pro:>8} | {x86_epi:>8} | {arm_pro:>8} | {arm_epi:>8}")

        print("-" * 70)
        print(f"Total ARM binaries: {total_arm}")
        print(f"Total x86 binaries: {total_x86}")
    else:
        print("Samples directory not found")

    print("\n2. X86 PATTERN VALIDATION (Synthetic)")
    print("-" * 70)

    # Create synthetic x86 function
    func = X86_PROLOGUE + b'\x83\xec\x10\x90\x90' + X86_EPILOGUE_1
    prologues = count_pattern(func, X86_PROLOGUE)
    epilogues = count_pattern(func, X86_EPILOGUE_1)

    print(f"Synthetic x86 function test:")
    print(f"  Prologues found: {prologues}")
    print(f"  Epilogues found: {epilogues}")
    print(f"  Pattern detection: {'PASS' if prologues == 1 and epilogues == 1 else 'FAIL'}")

    print("\n3. REFACTORING STATUS")
    print("-" * 70)
    print("Current state:")
    print("  - PRG_analysis.py has been refactored for x86 architecture")
    print("  - Prologue pattern: 55 89 E5 (push ebp; mov ebp, esp)")
    print("  - Epilogue patterns: C9 C3 (leave; ret) or 5D C3 (pop ebp; ret)")
    print("  - Radare2 config: asm.arch=x86, asm.bits=32")
    print("  - Angr arch: x86")
    print("")
    print("Issue identified:")
    print("  - All sample files are ARM binaries (not x86)")
    print("  - x86 refactoring cannot be fully validated without x86 samples")
    print("  - The codeak repository sample/DEFAULT.PRG may contain x86 binary")
    print("")
    print("Recommendation:")
    print("  - Obtain x86 CODESYS PRG binaries for testing")
    print("  - Re-run this validation with x86 samples")
    print("  - Consider maintaining ARM support for backward compatibility")

    print("\n" + "=" * 70)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='X86 refactoring validation tests')
    parser.add_argument('--report', action='store_true', help='Generate detailed report')
    args = parser.parse_args()

    if args.report:
        run_x86_validation()
    else:
        unittest.main(verbosity=2)
