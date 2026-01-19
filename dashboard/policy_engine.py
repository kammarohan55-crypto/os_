# Dynamic Policy Engine
# Risk-based decision making for sandbox enforcement

import yaml
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import json
from pathlib import Path


@dataclass
class PolicyAction:
    """Represents a policy enforcement action"""
    action_type: str  # KILL, THROTTLE_CPU, RESTRICT_NETWORK, TIGHTEN_SECCOMP, RELAX, ALERT
    params: Dict[str, Any]
    reason: str
    timestamp: float
    triggered_by_rule: str
    
    def to_dict(self):
        return asdict(self)


class PolicyEngine:
    """
    YAML-based policy engine for dynamic sandbox enforcement
    
    Features:
    - Condition-based rule evaluation
    - Multiple action types (kill, throttle, restrict, alert)
    - Full audit trail
    - Risk score integration
    """
    
    def __init__(self, policy_file=None):
        self.policy = None
        self.audit_log = []
        self.audit_file = "logs/policy_audit.jsonl"
        
        # Ensure logs directory exists
        Path("logs").mkdir(exist_ok=True)
        
        if policy_file:
            self.load_policy(policy_file)
        else:
            # Use default built-in policy
            self.policy = self._default_policy()
    
    def _default_policy(self):
        """Built-in default policy"""
        return {
            'name': 'Default Adaptive Policy',
            'version': '1.0',
            'description': 'Risk-based sandbox enforcement',
            'rules': [
                {
                    'name': 'Critical Risk - Immediate Kill',
                    'condition': {
                        'risk_score': {'gte': 90},
                        'or': [
                            {'syscall_rate': {'gte': 10000}},
                            {'peak_cpu': {'gte': 95}}
                        ]
                    },
                    'actions': [
                        {
                            'type': 'KILL',
                            'reason': 'Critical risk: excessive malicious activity',
                            'log_level': 'ALERT'
                        }
                    ]
                },
                {
                    'name': 'High Risk - Network Restriction',
                    'condition': {
                        'risk_score': {'gte': 70},
                        'network_connects': {'gte': 5}
                    },
                    'actions': [
                        {
                            'type': 'RESTRICT_NETWORK',
                            'method': 'drop_all_outbound',
                            'reason': 'Suspicious: multiple connection attempts',
                            'log_level': 'WARNING'
                        }
                    ]
                },
                {
                    'name': 'Medium Risk - CPU Throttle',
                    'condition': {
                        'risk_score': {'gte': 60},
                        'peak_cpu': {'gte': 90}
                    },
                    'actions': [
                        {
                            'type': 'THROTTLE_CPU',
                            'quota': '20%',
                            'duration_sec': 5,
                            'reason': 'Resource abuse detected',
                            'log_level': 'WARNING'
                        }
                    ]
                },
                {
                    'name': 'Elevated Risk - Tighten Controls',
                    'condition': {
                        'risk_score': {'gte': 50}
                    },
                    'actions': [
                        {
                            'type': 'TIGHTEN_SECCOMP',
                            'profile': 'STRICT',
                            'reason': 'Elevated risk: switching to strict mode',
                            'log_level': 'INFO'
                        }
                    ]
                },
                {
                    'name': 'Low Risk - Relax for Analysis',
                    'condition': {
                        'risk_score': {'lt': 30},
                        'runtime_ms': {'gte': 10000}
                    },
                    'actions': [
                        {
                            'type': 'RELAX',
                            'profile': 'LEARNING',
                            'reason': 'Low risk: enabling more syscalls for analysis',
                            'log_level': 'INFO'
                        }
                    ]
                }
            ]
        }
    
    def load_policy(self, policy_file):
        """Load policy from YAML file"""
        try:
            with open(policy_file, 'r') as f:
                self.policy = yaml.safe_load(f)
            print(f"[Policy] Loaded policy: {self.policy.get('name')}")
        except Exception as e:
            print(f"[Policy] Failed to load {policy_file}: {e}")
            print("[Policy] Using default built-in policy")
            self.policy = self._default_policy()
    
    def evaluate(self, context: Dict[str, Any]) -> List[PolicyAction]:
        """
        Evaluate policy rules against current context
        
        Args:
            context: dict with metrics like:
                {
                    'risk_score': 85.2,
                    'syscall_rate': 12000,
                    'network_connects': 3,
                    'peak_cpu': 95,
                    'runtime_ms': 2500,
                    'peak_memory_kb': 50000
                }
        
        Returns:
            list of PolicyAction objects to execute
        """
        actions = []
        
        for rule in self.policy.get('rules', []):
            if self._eval_condition(rule['condition'], context):
                rule_name = rule.get('name', 'Unnamed Rule')
                
                for action_spec in rule.get('actions', []):
                    action = PolicyAction(
                        action_type=action_spec['type'],
                        params={k: v for k, v in action_spec.items() 
                               if k not in ['type', 'reason', 'log_level']},
                        reason=action_spec.get('reason', 'No reason provided'),
                        timestamp=time.time(),
                        triggered_by_rule=rule_name
                    )
                    actions.append(action)
                    
                    # Log to audit trail
                    self._audit(action, context, action_spec.get('log_level', 'INFO'))
                
                # First matching rule wins (can change to evaluate all)
                break
        
        return actions
    
    def _eval_condition(self, condition: Dict, context: Dict) -> bool:
        """
        Evaluate a condition dict against context
        
        Supports:
        - Simple comparisons: {'risk_score': {'gte': 90}}
        - AND (implicit): multiple keys
        - OR: {'or': [cond1, cond2]}
        """
        # Handle OR logic
        if 'or' in condition:
            return any(self._eval_condition(c, context) for c in condition['or'])
        
        # Handle AND logic (all conditions must match)
        for key, value in condition.items():
            if key == 'or':
                continue
            
            context_value = context.get(key, 0)
            
            if isinstance(value, dict):
                # Comparison operators
                if 'gte' in value and not (context_value >= value['gte']):
                    return False
                if 'lte' in value and not (context_value <= value['lte']):
                    return False
                if 'gt' in value and not (context_value > value['gt']):
                    return False
                if 'lt' in value and not (context_value < value['lt']):
                    return False
                if 'eq' in value and not (context_value == value['eq']):
                    return False
            else:
                # Direct equality
                if context_value != value:
                    return False
        
        return True
    
    def _audit(self, action: PolicyAction, context: Dict, log_level: str):
        """Log action to audit trail"""
        audit_entry = {
            'timestamp': action.timestamp,
            'log_level': log_level,
            'action': action.to_dict(),
            'context': context
        }
        
        self.audit_log.append(audit_entry)
        
        # Append to JSONL file
        try:
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
        except Exception as e:
            print(f"[Policy] Audit log write failed: {e}")
        
        # Console log
        print(f"[Policy-{log_level}] {action.triggered_by_rule}: {action.action_type} - {action.reason}")
    
    def get_audit_log(self, limit=100):
        """Retrieve recent audit entries"""
        return self.audit_log[-limit:]
    
    def export_policy_yaml(self, output_file):
        """Export current policy to YAML file"""
        with open(output_file, 'w') as f:
            yaml.dump(self.policy, f, default_flow_style=False)
        print(f"[Policy] Exported policy to {output_file}")


# Example usage
if __name__ == '__main__':
    engine = PolicyEngine()
    
    # Test scenario: High-risk malware
    malware_context = {
        'risk_score': 92.3,
        'syscall_rate': 15000,
        'network_connects': 8,
        'peak_cpu': 98,
        'runtime_ms': 3500,
        'peak_memory_kb': 80000
    }
    
    actions = engine.evaluate(malware_context)
    print(f"\n[Test] Malware scenario triggered {len(actions)} action(s):")
    for action in actions:
        print(f"  - {action.action_type}: {action.reason}")
    
    # Test scenario: Benign program
    benign_context = {
        'risk_score': 15.8,
        'syscall_rate': 120,
        'network_connects': 0,
        'peak_cpu': 12,
        'runtime_ms': 250,
        'peak_memory_kb': 2048
    }
    
    actions = engine.evaluate(benign_context)
    print(f"\n[Test] Benign scenario triggered {len(actions)} action(s):")
    for action in actions:
        print(f"  - {action.action_type}: {action.reason}")
    
    # Export policy
    engine.export_policy_yaml('policies/default_policy.yaml')
