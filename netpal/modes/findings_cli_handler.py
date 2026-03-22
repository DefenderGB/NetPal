"""Handler for the 'findings' subcommand."""
from colorama import Fore, Style
from .base_handler import ModeHandler


class FindingsCLIHandler(ModeHandler):
    """Handles findings viewing via CLI subcommand."""
    
    def __init__(self, netpal_instance, args):
        super().__init__(netpal_instance)
        self.args = args
    
    def display_banner(self):
        print(f"\n{Fore.CYAN}  ▸ Security Findings{Style.RESET_ALL}\n")
    
    def validate_prerequisites(self):
        if getattr(self.args, 'create', False):
            if not self.project:
                print(f"{Fore.RED}[ERROR] No active project.{Style.RESET_ALL}")
                return False
            if not self.project.hosts:
                print(f"{Fore.RED}[ERROR] No hosts in project. Run discovery first.{Style.RESET_ALL}")
                return False
            return True

        if not self.project.findings:
            print(f"{Fore.YELLOW}No findings in project.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[TIP] Run: netpal ai-review{Style.RESET_ALL}")
            return False
        return True
    
    def prepare_context(self):
        return {'args': self.args}
    
    def execute_workflow(self, context):
        from ..utils.display.finding_viewer import display_findings_summary

        if getattr(self.args, 'create', False):
            self._run_create_wizard()
            return True
        
        findings = self.project.findings
        
        # Apply filters
        if self.args.severity:
            findings = [f for f in findings if f.severity == self.args.severity]
        if self.args.host:
            host_ids = [h.host_id for h in self.project.hosts if h.ip == self.args.host]
            findings = [f for f in findings if f.host_id in host_ids]
        
        # Handle delete
        if self.args.delete:
            return self._delete_finding(self.args.delete)
        
        # Display
        if self.args.format == 'json':
            import json
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            display_findings_summary(findings, self.project.hosts)
        
        return True

    def _run_create_wizard(self):
        """Interactive wizard for manual finding creation."""
        from ..utils.finding_factory import create_finding_headless

        try:
            hosts = list(self.project.hosts)
            duplicate_ips = {host.ip for host in hosts if len(self.project.get_hosts_by_ip(host.ip)) > 1}

            print(f"{Fore.CYAN}Select a host:{Style.RESET_ALL}")
            for i, host in enumerate(hosts, 1):
                label = host.hostname or ""
                network = f" [{host.network_id}]" if host.ip in duplicate_ips else ""
                suffix = f" ({label})" if label else ""
                print(f"  {Fore.CYAN}{i}{Style.RESET_ALL}. {host.ip}{network}{suffix}")

            selected_host = None
            while selected_host is None:
                choice = input(f"{Fore.CYAN}Host number: {Style.RESET_ALL}").strip()
                try:
                    idx = int(choice)
                    if 1 <= idx <= len(hosts):
                        selected_host = hosts[idx - 1]
                    else:
                        print(f"{Fore.RED}Invalid selection. Enter a number between 1 and {len(hosts)}.{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Invalid input. Enter a number.{Style.RESET_ALL}")

            services = selected_host.services
            selected_port = None
            if services:
                print(f"\n{Fore.CYAN}Select a port:{Style.RESET_ALL}")
                for i, svc in enumerate(services, 1):
                    svc_label = svc.service_name or "unknown"
                    print(f"  {Fore.CYAN}{i}{Style.RESET_ALL}. {svc.port}/{svc.protocol} ({svc_label})")

                while selected_port is None:
                    choice = input(f"{Fore.CYAN}Port number: {Style.RESET_ALL}").strip()
                    try:
                        idx = int(choice)
                        if 1 <= idx <= len(services):
                            selected_port = services[idx - 1].port
                        else:
                            print(f"{Fore.RED}Invalid selection. Enter a number between 1 and {len(services)}.{Style.RESET_ALL}")
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Enter a number.{Style.RESET_ALL}")
            else:
                while selected_port is None:
                    choice = input(f"{Fore.CYAN}Port number: {Style.RESET_ALL}").strip()
                    try:
                        selected_port = int(choice)
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Enter a valid port number.{Style.RESET_ALL}")

            name = ""
            while not name.strip():
                name = input(f"\n{Fore.CYAN}Finding name: {Style.RESET_ALL}")
                if not name.strip():
                    print(f"{Fore.RED}Finding name is required.{Style.RESET_ALL}")

            severity_options = ["Critical", "High", "Medium", "Low", "Info"]
            print(f"\n{Fore.CYAN}Select severity:{Style.RESET_ALL}")
            for i, sev in enumerate(severity_options, 1):
                print(f"  {Fore.CYAN}{i}{Style.RESET_ALL}. {sev}")

            severity = None
            while severity is None:
                choice = input(f"{Fore.CYAN}Severity [1-5]: {Style.RESET_ALL}").strip()
                try:
                    idx = int(choice)
                    if 1 <= idx <= 5:
                        severity = severity_options[idx - 1]
                    else:
                        print(f"{Fore.RED}Invalid selection. Enter a number between 1 and 5.{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Invalid input. Enter a number.{Style.RESET_ALL}")

            cvss = None
            while True:
                cvss_input = input(f"\n{Fore.CYAN}CVSS score (0.0-10.0, empty to skip): {Style.RESET_ALL}").strip()
                if not cvss_input:
                    break
                try:
                    cvss_val = float(cvss_input)
                    if 0.0 <= cvss_val <= 10.0:
                        cvss = cvss_val
                        break
                    print(f"{Fore.RED}CVSS must be between 0.0 and 10.0.{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Invalid input. Enter a number between 0.0 and 10.0.{Style.RESET_ALL}")

            cwe_input = input(f"\n{Fore.CYAN}CWE identifier (empty to skip): {Style.RESET_ALL}").strip()
            cwe = cwe_input if cwe_input else None

            description = ""
            while not description.strip():
                description = input(f"\n{Fore.CYAN}Description: {Style.RESET_ALL}")
                if not description.strip():
                    print(f"{Fore.RED}Description is required.{Style.RESET_ALL}")

            impact = ""
            while not impact.strip():
                impact = input(f"\n{Fore.CYAN}Impact: {Style.RESET_ALL}")
                if not impact.strip():
                    print(f"{Fore.RED}Impact is required.{Style.RESET_ALL}")

            remediation = ""
            while not remediation.strip():
                remediation = input(f"\n{Fore.CYAN}Remediation: {Style.RESET_ALL}")
                if not remediation.strip():
                    print(f"{Fore.RED}Remediation is required.{Style.RESET_ALL}")

            proof_file = None
            all_proofs = []
            for svc in selected_host.services:
                for proof in svc.proofs:
                    file_path = proof.get("result_file") or proof.get("screenshot_file") or proof.get("http_file")
                    if file_path:
                        all_proofs.append({
                            "port": svc.port,
                            "type": proof.get("type", "unknown"),
                            "file": file_path,
                        })

            if all_proofs:
                print(f"\n{Fore.CYAN}Available proofs:{Style.RESET_ALL}")
                for i, proof in enumerate(all_proofs, 1):
                    print(f"  {Fore.CYAN}{i}{Style.RESET_ALL}. [{proof['port']}] {proof['type']} - {proof['file']}")

                while True:
                    proof_input = input(f"{Fore.CYAN}Select proofs (comma-separated numbers, empty to skip): {Style.RESET_ALL}").strip()
                    if not proof_input:
                        break
                    try:
                        indices = [int(x.strip()) for x in proof_input.split(",")]
                        if all(1 <= idx <= len(all_proofs) for idx in indices):
                            selected_files = [all_proofs[idx - 1]["file"] for idx in indices]
                            proof_file = ",".join(selected_files)
                            break
                        print(f"{Fore.RED}Invalid selection. Enter numbers between 1 and {len(all_proofs)}.{Style.RESET_ALL}")
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Enter comma-separated numbers.{Style.RESET_ALL}")

            finding = create_finding_headless(
                project=self.project,
                host_id=selected_host.host_id,
                port=selected_port,
                name=name.strip(),
                severity=severity,
                description=description.strip(),
                impact=impact.strip(),
                remediation=remediation.strip(),
                cvss=cvss,
                cwe=cwe,
                proof_file=proof_file,
            )

            print(f"{Fore.GREEN}[SUCCESS] Created finding: {finding.name} ({finding.finding_id}){Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Finding creation cancelled.{Style.RESET_ALL}")

    def _delete_finding(self, finding_id):
        from ..utils.persistence.project_persistence import delete_finding_from_project

        if delete_finding_from_project(self.project, finding_id):
            print(f"{Fore.GREEN}[SUCCESS] Deleted finding {finding_id}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[ERROR] Finding '{finding_id}' not found{Style.RESET_ALL}")
            return False
    
    def save_results(self, result):
        pass
    
    def suggest_next_command(self, result):
        pass  # End of pipeline
