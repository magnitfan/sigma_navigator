#!/usr/bin/env python3

"""
Sigma Rules to MITRE ATT&CK Navigator Converter
"""

import os
import sys
import json
import yaml
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import hashlib
from datetime import datetime

# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

MITRE_TACTICS = {
    'reconnaissance': 'TA0043',
    'resource-development': 'TA0042',
    'initial-access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege-escalation': 'TA0004',
    'stealth': 'TA0005',
    'credential-access': 'TA0006',
    'discovery': 'TA0007',
    'lateral-movement': 'TA0008',
    'collection': 'TA0009',
    'command-and-control': 'TA0011',
    'exfiltration': 'TA0010',
    'impact': 'TA0040',
    'defense-impairment': 'TA0112',
}

COLOR_SCHEME = {
    'no_coverage': '#FFFFFF',
    'low': '#FFF2CC',
    'medium': '#FFD966',
    'high': '#92D050',
    'critical': '#00B050',
}

INHERITED_COLOR_SCHEME = {
    'no_coverage': '#FFFFFF',
    'low': '#FFF8E7',
    'medium': '#FFFACD',
    'high': '#F0F8D8',
    'critical': '#E8F5D8',
}

# ══════════════════════════════════════════════════════════════════════════════
# Dataclasses
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SigmaRule:
    title: str
    rule_id: str
    file_path: str
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    detection_count: int = 1

    def __hash__(self):
        return hash(self.rule_id)

@dataclass
class TechniqueMetadata:
    technique_id: str
    tactic: str
    rule_count: int = 0
    rules: List[str] = field(default_factory=list)
    cves: Set[str] = field(default_factory=set)
    inherited_rule_count: int = 0
    inherited_rules: List[str] = field(default_factory=list)
    inherited_cves: Set[str] = field(default_factory=set)

    def get_coverage_level(self) -> str:
        total_coverage = self.rule_count + self.inherited_rule_count
        if total_coverage == 0:
            return 'no_coverage'
        elif total_coverage <= 2:
            return 'low'
        elif total_coverage <= 5:
            return 'medium'
        elif total_coverage <= 10:
            return 'high'
        else:
            return 'critical'

    def get_coverage_type(self) -> str:
        if self.rule_count > 0 and self.inherited_rule_count > 0:
            return 'combined'
        elif self.inherited_rule_count > 0:
            return 'inherited'
        else:
            return 'direct'

    def get_color(self) -> str:
        coverage_type = self.get_coverage_type()
        coverage_level = self.get_coverage_level()
        if coverage_type == 'inherited':
            return INHERITED_COLOR_SCHEME.get(coverage_level, '#FFFFFF')
        return COLOR_SCHEME.get(coverage_level, '#FFFFFF')

@dataclass
class CoverageStatistics:
    total_rules: int = 0
    total_techniques_covered: int = 0
    total_tactics_covered: int = 0
    techniques_by_tactic: Dict[str, int] = field(default_factory=dict)
    coverage_percent_by_tactic: Dict[str, float] = field(default_factory=dict)
    unique_cves: Set[str] = field(default_factory=set)

# ══════════════════════════════════════════════════════════════════════════════
# Sigma parser
# ══════════════════════════════════════════════════════════════════════════════

class SigmaParser:
    def __init__(self, repo_path: str, logger: logging.Logger):
        self.repo_path = Path(repo_path)
        self.logger = logger
        self.rules: Dict[str, SigmaRule] = {}
        self.invalid_rules: List[Tuple[str, str]] = []

    def parse_repository(self) -> Dict[str, SigmaRule]:
        self.logger.info(f"Scanning repo:: {self.repo_path}")
        yml_files = list(self.repo_path.rglob('*.yml')) + list(self.repo_path.rglob('*.yaml'))
        self.logger.info(f"Found {len(yml_files)} Sigma rules files")

        for yml_file in yml_files:
            try:
                self._parse_single_rule(yml_file)
            except Exception as e:
                self.logger.warning(f"Parcing error {yml_file}: {str(e)}")
                self.invalid_rules.append((str(yml_file), str(e)))

        self.logger.info(f"Successfully parsed {len(self.rules)} rules")
        if self.invalid_rules:
            self.logger.warning(f"Found {len(self.invalid_rules)} rules with errors")
        return self.rules

    def _parse_single_rule(self, file_path: Path) -> None:
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                content = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"YAML parsing error: {e}")

        if not content or not isinstance(content, dict):
            return

        title = content.get('title', 'Unknown')
        rule_id = content.get('id', hashlib.md5(str(file_path).encode()).hexdigest()[:8])
        tags = content.get('tags', [])
        tactics, techniques, sub_techniques = self._extract_attack_tags(tags)
        cves = self._extract_cve_tags(tags)

        rule = SigmaRule(
            title=title,
            rule_id=rule_id,
            file_path=str(file_path),
            tactics=tactics,
            techniques=techniques,
            sub_techniques=sub_techniques,
            cves=cves
        )
        self.rules[rule_id] = rule

    @staticmethod
    def _extract_attack_tags(tags: List[str]) -> Tuple[List[str], List[str], List[str]]:
        tactics = []
        techniques = []
        sub_techniques = []

        for tag in tags:
            if not isinstance(tag, str):
                continue

            tag_lower = tag.lower()
            if 'attack.' not in tag_lower:
                continue

            tag_part = tag_lower.replace('attack.', '')

            if tag_part.startswith('t'):
                if '.' in tag_part or '_' in tag_part:
                    normalized = tag_part.replace('.', '_')
                    sub_techniques.append(normalized)
                else:
                    techniques.append(tag_part)
            else:
                if tag_part in MITRE_TACTICS:
                    tactics.append(tag_part)

        return tactics, techniques, sub_techniques

    @staticmethod
    def _extract_cve_tags(tags: List[str]) -> List[str]:
        cves = []
        for tag in tags:
            if isinstance(tag, str) and tag.lower().startswith('cve.'):
                cves.append(tag.upper())
        return cves

# ══════════════════════════════════════════════════════════════════════════════
# MITRE Navigator generator
# ══════════════════════════════════════════════════════════════════════════════

class MITRENavigatorGenerator:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.coverage_data: Dict[str, TechniqueMetadata] = {}
        self.statistics = CoverageStatistics()

    def build_coverage_from_rules(self, rules: Dict[str, SigmaRule]) -> None:
        self.logger.info("Coverage building...")

        coverage_by_technique = defaultdict(lambda: TechniqueMetadata(
            technique_id='',
            tactic='',
            rule_count=0,
            rules=[],
            cves=set()
        ))

        inherited_coverage = defaultdict(lambda: {
            'rule_count': 0,
            'rules': set(),
            'cves': set(),
        })

        unique_cves = set()

        # ════════════════════════════════════════════════════════════════
        # 1st run: direct coverage
        # ════════════════════════════════════════════════════════════════

        for rule in rules.values():
            if rule.techniques:
                for tech in rule.techniques:
                    if rule.tactics:
                        for tactic in rule.tactics:
                            key = f"{tactic}:{tech}"
                            if key not in coverage_by_technique:
                                coverage_by_technique[key] = TechniqueMetadata(
                                    technique_id=tech,
                                    tactic=tactic,
                                    rule_count=0,
                                    rules=[],
                                    cves=set()
                                )
                            coverage_by_technique[key].rule_count += 1
                            coverage_by_technique[key].rules.append(rule.rule_id)
                            coverage_by_technique[key].cves.update(rule.cves)
                            unique_cves.update(rule.cves)

        # ════════════════════════════════════════════════════════════════
        # 2nd run: subtechniques + parent aggregation
        # ════════════════════════════════════════════════════════════════

        for rule in rules.values():
            if rule.sub_techniques:
                for sub_tech in rule.sub_techniques:
                    main_tech = sub_tech.split('_')[0]
                    if rule.tactics:
                        for tactic in rule.tactics:
                            sub_key = f"{tactic}:{sub_tech}"
                            if sub_key not in coverage_by_technique:
                                coverage_by_technique[sub_key] = TechniqueMetadata(
                                    technique_id=sub_tech,
                                    tactic=tactic,
                                    rule_count=0,
                                    rules=[],
                                    cves=set()
                                )
                            coverage_by_technique[sub_key].rule_count += 1
                            coverage_by_technique[sub_key].rules.append(rule.rule_id)
                            coverage_by_technique[sub_key].cves.update(rule.cves)

                            parent_key = f"{tactic}:{main_tech}"
                            inherited_coverage[parent_key]['rule_count'] += 1
                            inherited_coverage[parent_key]['rules'].add(rule.rule_id)
                            inherited_coverage[parent_key]['cves'].update(rule.cves)
                            unique_cves.update(rule.cves)

        # ════════════════════════════════════════════════════════════════
        # 3rd run: inherited
        # ════════════════════════════════════════════════════════════════

        for parent_key, inherited_data in inherited_coverage.items():
            tactic, main_tech = parent_key.split(':')
            if parent_key not in coverage_by_technique:
                coverage_by_technique[parent_key] = TechniqueMetadata(
                    technique_id=main_tech,
                    tactic=tactic,
                    rule_count=0,
                    rules=[],
                    cves=set()
                )

            coverage_by_technique[parent_key].inherited_rule_count = inherited_data['rule_count']
            coverage_by_technique[parent_key].inherited_rules = list(inherited_data['rules'])
            coverage_by_technique[parent_key].inherited_cves = inherited_data['cves']

        self.coverage_data = dict(coverage_by_technique)
        self.statistics.unique_cves = unique_cves
        self.statistics.total_rules = len(rules)
        self._calculate_statistics()
        self.logger.info(f"Successfully built coverage map: {len(self.coverage_data)} techniques covered")

    def _calculate_statistics(self) -> None:
        techniques_per_tactic = defaultdict(set)
        for key, meta in self.coverage_data.items():
            tactic = meta.tactic
            techniques_per_tactic[tactic].add(meta.technique_id)

        self.statistics.total_tactics_covered = len(techniques_per_tactic)
        self.statistics.total_techniques_covered = len(self.coverage_data)
        self.statistics.techniques_by_tactic = {
            tactic: len(techs) for tactic, techs in techniques_per_tactic.items()
        }

    def generate_navigator_layer(
        self,
        name: str = "4RAYS Sigma Rules Coverage",
        description: str = "Coverage of 4 RAYS Sigma detection rules against MITRE ATT&CK",
        domain: str = "enterprise-attack",
        attack_version: str = "19",
        navigator_version: str = "5.1.0",
        layer_version: str = "4.5",
    ) -> Dict:
        self.logger.info("Generating Navigator layer...")

        techniques_list = []
        for key, metadata in self.coverage_data.items():
            technique_id = (
                metadata.technique_id.upper()
                if not metadata.technique_id.startswith('T')
                else metadata.technique_id
            )
            technique_id = technique_id.replace('_', '.')

            coverage_type = metadata.get_coverage_type()
            if coverage_type == 'direct':
                comment = f"{metadata.rule_count} direct rules"
            elif coverage_type == 'inherited':
                comment = f"{metadata.inherited_rule_count} subtechnique rules"
            else:
                comment = f"{metadata.rule_count} + {metadata.inherited_rule_count} total rules"

            technique = {
                "techniqueID": technique_id,
                "tactic": metadata.tactic,
                "color": metadata.get_color(),
                "comment": comment,
                "enabled": True,
                "metadata": [
                    {
                        "name": "rule_count",
                        "value": str(metadata.rule_count)
                    },
                    {
                        "name": "inherited_rule_count",
                        "value": str(metadata.inherited_rule_count)
                    },
                    {
                        "name": "coverage_level",
                        "value": metadata.get_coverage_level()
                    },
                    {
                        "name": "coverage_type",
                        "value": coverage_type
                    }
                ]
            }

            all_cves = set(metadata.cves) | metadata.inherited_cves
            if all_cves:
                technique["metadata"].append({
                    "name": "cves",
                    "value": ", ".join(sorted(all_cves))
                })

            techniques_list.append(technique)

        layer = {
            "name": name,
            "description": description,
            "domain": domain,
            "versions": {
                "attack": attack_version,
                "navigator": navigator_version,
                "layer": layer_version,
            },
            "filters": {
                "platforms": [
                    "Windows", "Linux", "macOS", "Azure AD", "Office 365",
                    "SaaS", "IaaS", "Google Workspace", "PRE", "Network", "Containers",
                ]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#FFFFFF", "#FFD966", "#92D050", "#00B050"],
                "minValue": 0,
                "maxValue": 15,
            },
            "legendItems": [
                {"label": "No Coverage", "color": COLOR_SCHEME["no_coverage"]},
                {"label": "Low (direct)", "color": COLOR_SCHEME["low"]},
                {"label": "Medium (direct)", "color": COLOR_SCHEME["medium"]},
                {"label": "High (direct)", "color": COLOR_SCHEME["high"]},
                {"label": "Critical (direct)", "color": COLOR_SCHEME["critical"]},
                {"label": "Low (inherited via subtechniques)", "color": INHERITED_COLOR_SCHEME["low"]},
                {"label": "Medium (inherited via subtechniques)", "color": INHERITED_COLOR_SCHEME["medium"]},
                {"label": "High (inherited via subtechniques)", "color": INHERITED_COLOR_SCHEME["high"]},
                {"label": "Critical (inherited via subtechniques)", "color": INHERITED_COLOR_SCHEME["critical"]},
            ],
            "metadata": [
                {
                    "name": "total_rules",
                    "value": str(self.statistics.total_rules),
                },
                {
                    "name": "total_techniques_covered",
                    "value": str(self.statistics.total_techniques_covered),
                },
                {
                    "name": "total_tactics_covered",
                    "value": str(self.statistics.total_tactics_covered),
                },
                {
                    "name": "unique_cves",
                    "value": str(len(self.statistics.unique_cves)),
                },
                {
                    "name": "generated_at",
                    "value": datetime.now().isoformat(),
                },
            ],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        self.logger.info(f"Successfully generated Navigator layer: {len(techniques_list)} techniques")
        return layer

    def export_to_file(self, layer: Dict, output_path: str) -> None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(layer, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Navigator layer exported: {output_path}")
        print(f"\nNavigator layer saved: {output_path}")

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Sigma Rules to MITRE ATT&CK Navigator Converter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
python sigma_navigator.py --repo-path /path/to/sigma --output layer.json
python sigma_navigator.py -r ./rules -o navigator_layer.json -v
"""
    )

    parser.add_argument(
        '-r', '--repo-path',
        required=True,
        help='Sigma rules repo path'
    )
    parser.add_argument(
        '-o', '--output',
        default='4rays_sigma_mitre_coverage.json',
        help='Output json file path'
    )
    parser.add_argument(
        '-n', '--name',
        default='4RAYS Sigma Rules Coverage',
        help='Layer Name'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose'
    )

    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    logger.info("=" * 80)
    logger.info("Sigma Rules to MITRE ATT&CK Navigator Converter")
    logger.info("=" * 80)

    sigma_parser = SigmaParser(args.repo_path, logger)
    rules = sigma_parser.parse_repository()

    if not rules:
        logger.error("No sigma rules found")
        sys.exit(1)

    nav_generator = MITRENavigatorGenerator(logger)
    nav_generator.build_coverage_from_rules(rules)
    layer = nav_generator.generate_navigator_layer(name=args.name)
    nav_generator.export_to_file(layer, args.output)

if __name__ == '__main__':
    main()
