"""
Report generator for DDoS detection results.
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
from collections import defaultdict

from config.settings import Config


class DetectionReport:
    """Generates reports from detection logs."""
    
    def __init__(self, log_file: Path = None):
        """
        Initialize report generator.
        
        Args:
            log_file: Path to detection log file
        """
        self.log_file = log_file or Config.DETECTION_LOG
        self.predictions: List[Dict] = []
        self.stats: Dict = defaultdict(int)
    
    def parse_logs(self) -> None:
        """Parse detection logs and extract predictions."""
        if not self.log_file.exists():
            print(f"Log file not found: {self.log_file}")
            return
        
        # Patterns to match
        attack_pattern = re.compile(
            r'⚠️\s+DDoS ATTACK DETECTED!.*?\(Confidence:\s+([\d.]+)%\)'
        )
        normal_pattern = re.compile(
            r'✓\s+Normal traffic.*?\(Confidence:\s+([\d.]+)%\)'
        )
        timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
        
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
        
        current_timestamp = None
        
        for i, line in enumerate(lines):
            # Extract timestamp
            ts_match = timestamp_pattern.search(line)
            if ts_match:
                current_timestamp = ts_match.group(1)
            
            # Check for attack detection
            attack_match = attack_pattern.search(line)
            if attack_match:
                confidence = float(attack_match.group(1))
                self.predictions.append({
                    'timestamp': current_timestamp or 'Unknown',
                    'type': 'ATTACK',
                    'confidence': confidence,
                    'line': line.strip()
                })
                self.stats['total_attacks'] += 1
                self.stats['total_predictions'] += 1
                continue
            
            # Check for normal traffic
            normal_match = normal_pattern.search(line)
            if normal_match:
                confidence = float(normal_match.group(1))
                self.predictions.append({
                    'timestamp': current_timestamp or 'Unknown',
                    'type': 'NORMAL',
                    'confidence': confidence,
                    'line': line.strip()
                })
                self.stats['total_normal'] += 1
                self.stats['total_predictions'] += 1
                continue
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics."""
        if not self.predictions:
            return {
                'total_predictions': 0,
                'message': 'No predictions found in logs'
            }
        
        attack_confidences = [
            p['confidence'] for p in self.predictions if p['type'] == 'ATTACK'
        ]
        normal_confidences = [
            p['confidence'] for p in self.predictions if p['type'] == 'NORMAL'
        ]
        
        summary = {
            'total_predictions': len(self.predictions),
            'attacks_detected': self.stats['total_attacks'],
            'normal_traffic': self.stats['total_normal'],
            'attack_rate': (self.stats['total_attacks'] / len(self.predictions) * 100) if self.predictions else 0,
            'normal_rate': (self.stats['total_normal'] / len(self.predictions) * 100) if self.predictions else 0,
        }
        
        if attack_confidences:
            summary['avg_attack_confidence'] = sum(attack_confidences) / len(attack_confidences)
            summary['max_attack_confidence'] = max(attack_confidences)
            summary['min_attack_confidence'] = min(attack_confidences)
        
        if normal_confidences:
            summary['avg_normal_confidence'] = sum(normal_confidences) / len(normal_confidences)
            summary['max_normal_confidence'] = max(normal_confidences)
            summary['min_normal_confidence'] = min(normal_confidences)
        
        return summary
    
    def print_report(self) -> None:
        """Print formatted report to console."""
        print("=" * 70)
        print("DDoS Detection Report")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Log file: {self.log_file}")
        print()
        
        summary = self.generate_summary()
        
        if summary.get('total_predictions', 0) == 0:
            print("⚠️  No predictions found in logs.")
            print("   Make sure the detection system is running and has processed traffic.")
            return
        
        print("📊 SUMMARY STATISTICS")
        print("-" * 70)
        print(f"Total Predictions:     {summary['total_predictions']}")
        print(f"Attacks Detected:      {summary['attacks_detected']} ({summary['attack_rate']:.1f}%)")
        print(f"Normal Traffic:        {summary['normal_traffic']} ({summary['normal_rate']:.1f}%)")
        print()
        
        if summary.get('avg_attack_confidence'):
            print("🎯 ATTACK DETECTION CONFIDENCE")
            print("-" * 70)
            print(f"Average: {summary['avg_attack_confidence']:.2f}%")
            print(f"Maximum: {summary['max_attack_confidence']:.2f}%")
            print(f"Minimum: {summary['min_attack_confidence']:.2f}%")
            print()
        
        if summary.get('avg_normal_confidence'):
            print("✅ NORMAL TRAFFIC CONFIDENCE")
            print("-" * 70)
            print(f"Average: {summary['avg_normal_confidence']:.2f}%")
            print(f"Maximum: {summary['max_normal_confidence']:.2f}%")
            print(f"Minimum: {summary['min_normal_confidence']:.2f}%")
            print()
        
        print("📋 RECENT PREDICTIONS (Last 10)")
        print("-" * 70)
        recent = self.predictions[-10:] if len(self.predictions) > 10 else self.predictions
        for pred in recent:
            status = "🔴 ATTACK" if pred['type'] == 'ATTACK' else "🟢 NORMAL"
            print(f"{pred['timestamp']} | {status} | Confidence: {pred['confidence']:.2f}%")
        
        print()
        print("=" * 70)
    
    def save_json_report(self, output_file: Path = None) -> None:
        """Save report as JSON."""
        if output_file is None:
            output_file = Config.LOGS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'log_file': str(self.log_file),
            'summary': self.generate_summary(),
            'predictions': self.predictions
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"📄 Report saved to: {output_file}")


def main():
    """Main function to generate report."""
    report = DetectionReport()
    report.parse_logs()
    report.print_report()
    
    # Ask if user wants to save JSON report
    save_json = input("\nSave JSON report? (y/n): ").lower().strip()
    if save_json == 'y':
        report.save_json_report()


if __name__ == '__main__':
    main()

