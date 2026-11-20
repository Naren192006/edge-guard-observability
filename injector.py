#!/usr/bin/env python3
"""
VeilOps Scenario Injector CLI
Usage:
    python injector.py inject secret
    python injector.py inject outage 90s
    python injector.py inject authburst
    python injector.py inject latency
    python injector.py inject cpu
    python injector.py inject cascade
    python injector.py inject dup-ooo
    python injector.py inject remediate
"""

import sys
import json
from simulator.scenario_injector import ScenarioInjector

def print_banner(scenario_name: str):
    print("=" * 65)
    print(f"  VeilOps Scenario Injector: {scenario_name.upper()}")
    print("=" * 65)

def main():
    if len(sys.argv) < 2 or sys.argv[1] != "inject":
        print(__doc__)
        sys.exit(1)

    scenario = sys.argv[2] if len(sys.argv) > 2 else ""
    injector = ScenarioInjector()

    if scenario == "secret":
        print_banner("1. Raw Log Secret Leak Prevention")
        res = injector.run_secret_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "outage" or scenario.startswith("outage"):
        print_banner("2. SaaS Connectivity Outage & Drain")
        duration = 90
        if len(sys.argv) > 3 and sys.argv[3].endswith("s"):
            try:
                duration = int(sys.argv[3][:-1])
            except ValueError:
                pass
        res = injector.run_outage_scenario(duration)
        print(json.dumps(res, indent=2))
    elif scenario == "authburst":
        print_banner("3. Repeated Failed Logins")
        res = injector.run_authburst_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "latency":
        print_banner("4. Network Latency & Packet Loss Surge")
        res = injector.run_latency_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "cpu":
        print_banner("5. CPU Deviation from Seasonal Baseline")
        res = injector.run_cpu_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "cascade":
        print_banner("6. Uplink Failure Incident Cascade")
        res = injector.run_cascade_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "dup-ooo":
        print_banner("7. Duplicate & Out-of-Order Delivery")
        res = injector.run_dup_ooo_scenario()
        print(json.dumps(res, indent=2))
    elif scenario == "remediate":
        print_banner("8. Automated Remediation Simulation")
        res = injector.run_remediate_scenario()
        print(json.dumps(res, indent=2))
    else:
        print(f"Unknown scenario: '{scenario}'")
        print("Available: secret, outage, authburst, latency, cpu, cascade, dup-ooo, remediate")
        sys.exit(1)

if __name__ == "__main__":
    main()
