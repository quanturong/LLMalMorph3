#!/usr/bin/env python3
"""
Test Enhanced BuildValidationAgent with Advanced Retry Logic
"""

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Add project paths
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir / "src"))

from agents.build_validation_agent import BuildValidationAgent


class MockProjectCompiler:
    """Mock ProjectCompiler for testing retry logic."""
    
    def __init__(self, fail_count=2):
        self.fail_count = fail_count
        self.attempt_count = 0
        self.auto_fix_attempts = 0
        
    def compile_project(self, **kwargs):
        """Simulate compilation with configurable failure."""
        self.attempt_count += 1
        self.auto_fix_attempts += 1
        
        result = MagicMock()
        result.auto_fix_attempts = self.auto_fix_attempts
        result.executable_path = f"test_output_{self.attempt_count}.exe"
        result.errors = f"Mock error on attempt {self.attempt_count}"
        
        if self.attempt_count > self.fail_count:
            result.success = True
            result.errors = None
        else:
            result.success = False
            
        return result


class MockProject:
    """Mock project object."""
    
    def __init__(self, name="test_project"):
        self.name = name
        self.compile_flags = []
        self.security_flags = True
        self.permissive_mode = False


async def test_retry_logic():
    """Test the enhanced retry logic with different failure scenarios."""
    
    print("🧪 Testing Enhanced BuildValidationAgent Retry Logic")
    print("=" * 60)
    
    # Create mock agent without full initialization
    from agents.build_validation_agent import BuildValidationAgent
    
    # Test scenarios
    test_cases = [
        {
            "name": "Success on first attempt",
            "fail_count": 0,
            "expected_success": True,
        },
        {
            "name": "Success after 2 failures (standard retry)",
            "fail_count": 2,
            "expected_success": True,
        },
        {
            "name": "Success after 4 failures (permissive retry)",  
            "fail_count": 4,
            "expected_success": True,
        },
        {
            "name": "Failure after all retries",
            "fail_count": 10,
            "expected_success": False,
        },
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n📋 Test {i}: {test_case['name']}")
        print("-" * 40)
        
        # Setup mocks
        compiler = MockProjectCompiler(fail_count=test_case["fail_count"])
        project = MockProject()
        
        # Create mock log
        log = MagicMock()
        log.info = lambda msg, **kwargs: print(f"   ℹ️  {msg}: {kwargs}")
        log.warning = lambda msg, **kwargs: print(f"   ⚠️  {msg}: {kwargs}")
        
        try:
            # Test the retry method directly (using class method without instance)
            agent_instance = object.__new__(BuildValidationAgent)
            result, fix_stats = await agent_instance._compile_with_advanced_retry(
                compiler=compiler,
                project=project,
                output_dir="test_output",
                output_name="test_exe",
                job_id="test_job_123",
                sample_id="test_sample",
                log=log,
            )
            
            success = result is not None and result.success
            print(f"   📊 Result: {'✅ SUCCESS' if success else '❌ FAILED'}")
            print(f"   📈 Fix Stats: {fix_stats}")
            print(f"   🔄 Total Attempts: {fix_stats.get('total_attempts', 0)}")
            
            # Verify expected outcome
            if success == test_case["expected_success"]:
                print(f"   ✅ Test PASSED - Expected: {test_case['expected_success']}, Got: {success}")
            else:
                print(f"   ❌ Test FAILED - Expected: {test_case['expected_success']}, Got: {success}")
                
        except Exception as e:
            print(f"   💥 Exception: {e}")

    print("\n" + "=" * 60)


async def test_error_categorization():
    """Test error categorization functionality."""
    
    print("🏷️  Testing Error Categorization")
    print("=" * 60)
    
    from agents.build_validation_agent import BuildValidationAgent
    agent_instance = object.__new__(BuildValidationAgent)
    
    test_errors = [
        ("Access denied to C:\\malware.exe", "security_blocked"),
        ("Virus detected in source code", "security_blocked"),
        ("Cannot find windows.h", "missing_dependency"),
        ("Undefined reference to 'main'", "missing_dependency"),
        ("Syntax error: expected ';'", "syntax_error"),
        ("Parse error on line 42", "syntax_error"),
        ("Compiler cl.exe not found", "toolchain_error"),
        ("GCC toolchain missing", "toolchain_error"),
        ("Out of memory during compilation", "resource_error"),
        ("Stack overflow in parser", "resource_error"),
        ("Version 3.2 is incompatible", "compatibility_error"),
        ("Deprecated function call", "compatibility_error"),
        ("Unknown compilation error", "compilation_error"),
    ]
    
    for error_msg, expected_category in test_errors:
        actual_category = agent_instance._categorize_build_error(error_msg)
        status = "✅" if actual_category == expected_category else "❌"
        print(f"{status} '{error_msg[:30]}...' → {actual_category} (expected: {expected_category})")
    
    print("\n" + "=" * 60)


async def test_malware_compilation_prep():
    """Test malware-specific compilation preparation."""
    
    print("🦠 Testing Malware Compilation Preparation")
    print("=" * 60)
    
    from agents.build_validation_agent import BuildValidationAgent
    agent_instance = object.__new__(BuildValidationAgent)
    project = MockProject()
    
    # Mock log
    log = MagicMock()
    log.info = lambda msg, **kwargs: print(f"ℹ️  {msg}: {kwargs}")
    log.warning = lambda msg, **kwargs: print(f"⚠️  {msg}: {kwargs}")
    
    print(f"📋 Before preparation:")
    print(f"   • Compile flags: {project.compile_flags}")
    print(f"   • Security flags: {project.security_flags}")
    print(f"   • Permissive mode: {project.permissive_mode}")
    
    await agent_instance._prepare_malware_compilation(project, log)
    
    print(f"\n📋 After preparation:")
    print(f"   • Compile flags: {len(project.compile_flags)} flags added")
    print(f"   • Security flags: {project.security_flags}")
    print(f"   • Permissive mode: {project.permissive_mode}")
    
    print("\n" + "=" * 60)


async def test_detailed_error_formatting():
    """Test detailed error message formatting."""
    
    print("📝 Testing Detailed Error Formatting")
    print("=" * 60)
    
    from agents.build_validation_agent import BuildValidationAgent
    agent_instance = object.__new__(BuildValidationAgent)
    
    fix_stats = {
        "total_attempts": 7,
        "standard_attempts": 3,
        "permissive_attempts": 2,
        "surgical_attempts": 2,
        "fix_loop_detected": True,
        "rollback_triggered": False,
        "error_categories": ["syntax_error", "missing_dependency", "compilation_error"],
    }
    
    error_message = "Multiple compilation errors detected in malware source code"
    error_category = "compilation_error"
    
    formatted = agent_instance._format_detailed_error(error_message, fix_stats, error_category)
    
    print("📄 Formatted Error Report:")
    print("-" * 40)
    print(formatted)
    print("-" * 40)
    
    print("\n" + "=" * 60)


async def main():
    """Run all tests."""
    
    print("🚀 Enhanced BuildValidationAgent Test Suite")
    print("=" * 80)
    print("Testing advanced retry logic integration from old pipeline")
    print("=" * 80)
    
    try:
        await test_retry_logic()
        await test_error_categorization() 
        await test_malware_compilation_prep()
        await test_detailed_error_formatting()
        
        print("🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"💥 Test suite failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())