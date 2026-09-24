from .precommit_command import PreCommitCommand
from .pr_decorator_command import PRDecoratorCommand
from .scan_command import ScanCommand
from .tool_command import ToolCommand

command_registry = {
    "pre-commit": PreCommitCommand,
    "scan": ScanCommand,
    "tool": ToolCommand,
    "decorate-pr": PRDecoratorCommand,
}