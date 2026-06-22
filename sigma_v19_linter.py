import os
import sys
import yaml
import argparse
from pathlib import Path

# Setup safe YAML parser to ignore unknown Sigma-specific constructors
class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass

SafeLoaderIgnoreUnknown.add_constructor(None, lambda loader, node: None)

# Database of deprecated/modified artifacts for v19
# Keys must be lowercase and use hyphens to match your convention
V19_CHANGES = {
    "attack.defense-evasion": (
        "Tactic 'Defense Evasion' was removed. Replaced by 'Stealth' (TA0005) "
        "and the new tactic 'Defense Impairment' (TA0112)."
    ),
    "attack.t1562": (
        "Sub-techniques for T1562 (Impair Defenses) have been heavily restructured "
        "and moved to new tactics (e.g., T1685). Requires manual coverage review."
    )
}

def analyze_sigma_rule(filepath):
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Using load_all because a Sigma file might contain multiple documents separated by '---'
            docs = yaml.load_all(f, Loader=SafeLoaderIgnoreUnknown)
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                
                title = doc.get('title', 'Unknown Title')
                tags = doc.get('tags', [])
                
                if not tags:
                    continue
                
                for tag in tags:
                    # Normalize tag to lower case and replace underscores with hyphens just in case
                    tag_normalized = tag.lower().replace('_', '-')
                    
                    # Check for exact match
                    if tag_normalized in V19_CHANGES:
                        issues.append({
                            "title": title, 
                            "tag": tag, 
                            "tag_normalized": tag_normalized,
                            "reason": V19_CHANGES[tag_normalized]
                        })
                        continue
                    
                    # Check for prefixes (so attack.t1562.001 matches the attack.t1562 rule)
                    for key, reason in V19_CHANGES.items():
                        if tag_normalized.startswith(key + ".") and tag_normalized != key:
                            issues.append({
                                "title": title, 
                                "tag": tag,
                                "tag_normalized": tag_normalized,
                                "reason": reason
                            })

    except Exception as e:
        # We print parsing errors to stderr immediately, they won't go to the output file
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
        
    return issues

def main():
    parser = argparse.ArgumentParser(
        description='Sigma Rules MITRE ATT&CK v19 Compatibility Linter',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-r', '--repo-path',
        required=True,
        help='Local Sigma rules repository path (required)'
    )
    parser.add_argument(
        '-o', '--output',
        required=False,
        help='Output file path to save the linter report (optional)'
    )
    
    args = parser.parse_args()
    rules_dir = args.repo_path
    
    if not os.path.isdir(rules_dir):
        print(f"[!] Directory '{rules_dir}' not found. Please provide a valid path.")
        sys.exit(1)

    # Initialize variables for statistics and reporting
    total_checked = 0
    issues_found = 0
    
    # Using sets to prevent duplicate file paths if a file contains multiple problematic rules
    files_defense_evasion = set()
    files_t1562 = set()
    report_lines = []

    # Helper function to print to console and save to report simultaneously
    def log(message):
        print(message)
        report_lines.append(message)

    log("[*] Initializing MITRE ATT&CK v19 compatibility linter...")
    log(f"[*] Analyzing directory: {rules_dir}\n")
    
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                total_checked += 1
                filepath = Path(root) / file
                
                issues = analyze_sigma_rule(filepath)
                if issues:
                    issues_found += 1
                    log(f"[-] File: {filepath}")
                    
                    for issue in issues:
                        # Categorize the file based on the specific issue found
                        if issue['tag_normalized'].startswith("attack.defense-evasion"):
                            files_defense_evasion.add(str(filepath))
                        elif issue['tag_normalized'].startswith("attack.t1562"):
                            files_t1562.add(str(filepath))
                            
                        log(f"    Rule:   {issue['title']}")
                        log(f"    Tag:    {issue['tag']}")
                        log(f"    Reason: {issue['reason']}\n")
                    log("-" * 60)
                    
    log(f"\n[*] Scan completed. Rules analyzed: {total_checked}")
    log(f"[*] Files requiring MITRE tags update: {issues_found}")
    
    # Print the categorized summary lists at the very end
    if files_defense_evasion or files_t1562:
        log("\n[*] Summary of files requiring updates:")
        
        if files_defense_evasion:
            log("\n    [!] Category: Deprecated 'Defense Evasion' tactic")
            for faulty_file in sorted(files_defense_evasion):
                log(f"        - {faulty_file}")
                
        if files_t1562:
            log("\n    [!] Category: Deprecated 'T1562' (and sub-techniques)")
            for faulty_file in sorted(files_t1562):
                log(f"        - {faulty_file}")
            
    # Write to output file if argument was provided
    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(report_lines) + "\n")
            print(f"\n[+] Report successfully saved to: {args.output}")
        except Exception as e:
            print(f"\n[!] Failed to save report to {args.output}: {e}", file=sys.stderr)
    
    # Return non-zero exit code for CI/CD if issues were found
    if issues_found > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()