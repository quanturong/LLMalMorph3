"""
Base classes for language plugins.
All language plugins must inherit from Language class.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class Function:
    """Represents a function across all languages"""
    name: str
    name_with_params: str  # Full signature
    return_type: str
    parameters: List[Dict[str, Any]]  # [{"type": "int", "name": "x"}]
    body: str
    start_line: int
    end_line: int
    is_async: bool = False
    is_static: bool = False
    decorators: List[str] = field(default_factory=list)  # For Python
    visibility: str = "public"  # For OOP languages


@dataclass
class Class:
    """Represents a class across all languages"""
    name: str
    body: str
    start_line: int
    end_line: int
    methods: List[Function] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)  # Inheritance
    is_abstract: bool = False


@dataclass
class Module:
    """Represents a module/package/namespace"""
    name: str
    path: str
    exports: List[str] = field(default_factory=list)


@dataclass
class CodeStructure:
    """Unified code structure representation"""
    headers: List[str]  # imports, includes, requires
    globals: List[str]  # global variables, constants
    functions: List[Function]
    classes: List[Class]
    modules: List[Module] = field(default_factory=list)
    language: str = ""


class Language(ABC):
    """
    Base class for all language plugins.
    Each language must implement these methods.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Language name (e.g., 'python', 'c', 'cpp')"""
        pass
    
    @property
    @abstractmethod
    def extensions(self) -> List[str]:
        """List of file extensions (e.g., ['.py', '.pyw'])"""
        pass
    
    @abstractmethod
    def can_parse(self, content: str) -> bool:
        """
        Check if content can be parsed by this language.
        
        Args:
            content: Source code content
        
        Returns:
            True if content matches this language
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: str, content: str) -> CodeStructure:
        """
        Parse source code into unified structure.
        
        Args:
            file_path: Path to source file
            content: Source code content
        
        Returns:
            CodeStructure with parsed information
        
        Raises:
            ParseError: If parsing fails
        """
        pass
    
    @abstractmethod
    def get_parser(self):
        """
        Get language-specific parser instance.
        
        Returns:
            Parser instance (e.g., tree-sitter parser)
        """
        pass
    
    def get_system_prompt(self) -> str:
        """
        Get system prompt for LLM.
        Can be overridden for language-specific prompts.
        
        Returns:
            System prompt string
        """
        return (
            f"You are an intelligent coding assistant expert in {self.name}. "
            "You specialize in writing, editing, refactoring and debugging code. "
            "You listen to exact instructions and follow best practices."
        )
    
    def get_mutation_prompt(
        self,
        num_functions: int,
        function_names: List[str],
        strategy: str = "optimization"
    ) -> str:
        """
        Get mutation prompt for LLM.
        Can be overridden for language-specific prompts.
        
        Args:
            num_functions: Number of functions to mutate
            function_names: List of function names
            strategy: Mutation strategy
        
        Returns:
            Prompt string
        """
        func_list = ", ".join([f"***{name}***" for name in function_names])
        
        return f"""
Generate VARIANT(s) of {num_functions} function(s): {func_list}

Instructions:
1. Remove code redundancies
2. Identify performance bottlenecks and fix them
3. Simplify code logic or structure
4. Use language-specific features or modern libraries

REMEMBER: Maintain the same FUNCTIONALITY as the original code.
"""
    
    def normalize_function_name(self, name: str) -> str:
        """
        Normalize function name for comparison.
        Language-specific implementation.
        
        Args:
            name: Function name or signature
        
        Returns:
            Normalized name
        """
        return name.strip()
    
    def format_code_block(self, code: str) -> str:
        """
        Format code block for LLM response.
        
        Args:
            code: Source code
        
        Returns:
            Formatted code block with language tag
        """
        return f"```{self.name}\n{code}\n```"
    
    def validate_syntax(self, code: str) -> Tuple[bool, Optional[str]]:
        """
        Validate syntax of generated code.
        
        Args:
            code: Source code to validate
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Default: no validation (can be overridden)
        return True, None

