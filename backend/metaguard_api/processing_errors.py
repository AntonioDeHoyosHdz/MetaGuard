"""Shared private processor failures without file-parser imports."""


class ProcessingSupervisorError(RuntimeError):
    """Raised when an isolated processing job cannot safely complete."""


class ProcessingSupervisorCleanupError(ProcessingSupervisorError):
    """Container cleanup could not be confirmed; further work must stop."""
