"""Handler for the 'testcase' subcommand.

Manages test case list attachments, loading, status updates, and results
for the active project.
"""
from colorama import Fore, Style
from .base_handler import ModeHandler
from ..utils.display.display_utils import print_section_banner, print_success, print_error


class TestcaseHandler(ModeHandler):
    """Handles ``netpal testcase`` — test case management."""

    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args

    # ── Template-method steps ──────────────────────────────────────────

    def display_banner(self):
        print_section_banner("Test Cases")

    def validate_prerequisites(self) -> bool:
        if not self.project:
            print_error("No active project.")
            return False
        return True

    def prepare_context(self):
        return {}

    def execute_workflow(self, context):
        from ..services.testcase.manager import TestCaseManager

        mgr = TestCaseManager(self.config)

        # --load
        if getattr(self.args, "load", False):
            csv_path = getattr(self.args, "csv_path", "") or ""
            result = mgr.load_test_cases(self.project, csv_path=csv_path)
            if result.get("error"):
                print_error(result['error'])
                return False
            print_success(f"Loaded {result.get('total', 0)} test cases "
                  f"(source: {result.get('source', 'unknown')})")
            if result.get("added"):
                print(f"  Added: {result['added']}, Updated: {result.get('updated', 0)}, "
                      f"Retained: {result.get('retained', 0)}")
            return True

        # --set-result
        set_result_args = getattr(self.args, "set_result", None)
        if set_result_args:
            test_case_id, status = set_result_args
            notes = getattr(self.args, "notes", "") or ""
            result = mgr.set_result(self.project.project_id, test_case_id, status, notes)
            if result.get("error"):
                print_error(result['error'])
                return False
            print_success(result['message'])
            return True

        # --results
        if getattr(self.args, "results", False):
            phase = getattr(self.args, "phase", "") or ""
            status_filter = getattr(self.args, "status", "") or ""
            result = mgr.get_results(self.project.project_id, phase=phase, status=status_filter)
            summary = result.get("summary", {})
            print(f"  Passed: {Fore.GREEN}{summary.get('passed', 0)}{Style.RESET_ALL}  "
                  f"Failed: {Fore.RED}{summary.get('failed', 0)}{Style.RESET_ALL}  "
                  f"Needs Input: {Fore.YELLOW}{summary.get('needs_input', 0)}{Style.RESET_ALL}  "
                  f"Total: {summary.get('total', 0)}\n")
            for phase_name, entries in result.get("results", {}).items():
                print(f"  {Fore.CYAN}{phase_name}{Style.RESET_ALL}")
                for e in entries:
                    s = e.get("status", "needs_input")
                    color = Fore.GREEN if s == "passed" else Fore.RED if s == "failed" else Fore.YELLOW
                    print(f"    {color}[{s}]{Style.RESET_ALL} {e.get('test_name', '')} ({e.get('test_case_id', '')})")
                    if e.get("notes"):
                        print(f"          Notes: {e['notes']}")
            return True

        # No flags — show help hint
        print(f"{Fore.YELLOW}Use --load, --results, or --set-result{Style.RESET_ALL}")
        return True

    # ── Overrides ──────────────────────────────────────────────────────

    def save_results(self, result):
        pass  # Handled inline

    def sync_if_enabled(self):
        pass

    def display_completion(self, result):
        pass
