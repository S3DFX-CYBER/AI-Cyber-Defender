import os
import re
import logging
import yaml

logger = logging.getLogger(__name__)

class CustomRuleEngine:
    # Look for the config directory inside the analyzer service folder
    def __init__(self, config_path="services/analyzer/config/rules.yaml"):
        # Fallback to check relative path if running directly from the analyzer directory
        if not os.path.exists(config_path) and os.path.exists("config/rules.yaml"):
            config_path = "config/rules.yaml"
            
        self.rules = []
        self.load_rules(config_path)

    def load_rules(self, config_path):
        """Loads and compiles regex rules from the YAML configuration file."""
        if not os.path.exists(config_path):
            logger.info(f"Custom rules config not found at {config_path}. Using default heuristics only.")
            return

        try:
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file)
                if config and 'rules' in config:
                    self.rules = config['rules']
                    for rule in self.rules:
                        try:
                            rule['compiled_pattern'] = re.compile(rule['pattern'])
                        except re.error as e:
                            logger.error(f"Invalid regex pattern in rule '{rule.get('name')}': {e}")
                            rule['compiled_pattern'] = None
                    
                    logger.info(f"Successfully loaded {len(self.rules)} custom security rules.")
        except Exception as e:
            logger.error(f"Error loading custom rules from {config_path}: {e}")

    def evaluate(self, prompt: str) -> dict:
        """Evaluates a prompt against all loaded custom regex patterns."""
        triggered_rules = []
        highest_action = "ALLOW"

        for rule in self.rules:
            compiled_pattern = rule.get('compiled_pattern')
            if compiled_pattern and compiled_pattern.search(prompt):
                triggered_rules.append({
                    "rule_name": rule['name'],
                    "severity": rule['severity'],
                    "description": rule['description']
                })
                
                action = rule.get('action', 'FLAGGED').upper()
                if action == 'BLOCKED':
                    highest_action = 'BLOCKED'
                elif action == 'FLAGGED' and highest_action != 'BLOCKED':
                    highest_action = 'FLAGGED'

        return {
            "custom_rules_triggered": len(triggered_rules) > 0,
            "recommended_action": highest_action,
            "rule_hits": triggered_rules
        }