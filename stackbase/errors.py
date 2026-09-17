"""Shared error type for stack-base.

Every user-visible failure in stack-base is a StackError: a short message
describing what went wrong plus a hint telling the operator what to check.
The CLI entrypoint catches StackError at the top level and prints
`str(error)` as the single plain-English line required by the global
constraints -- no traceback unless --debug is passed.
"""


class StackError(Exception):
    """Raised for any expected, user-actionable failure in stack-base."""

    def __init__(self, message: str, hint: str) -> None:
        self.message = message
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        return f"{self.message} — {self.hint}"
