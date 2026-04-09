"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  src/utils/__init__.py — helper utilities
=============================================================
"""

def print_section(title, width=60, char='─'):
    """Print a styled section header."""
    from colorama import Fore
    print(Fore.CYAN + f"\n{char*width}")
    print(Fore.CYAN + f"  {title}")
    print(Fore.CYAN + f"{char*width}")


def print_step(step_num, description):
    """Print a numbered pipeline step."""
    from colorama import Fore
    print(Fore.YELLOW + f"\n[STEP {step_num}] {description}")


def format_bytes(size):
    """Convert bytes count to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
