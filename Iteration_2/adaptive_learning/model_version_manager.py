"""
Model Version Manager
Tracks model versions, performance, and evolution over time
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class ModelVersionManager:
    """
    Manages model versioning and tracks performance metrics across updates
    """
    
    def __init__(self, version_file: str = "adaptive_learning/model_version.json"):
        self.version_file = version_file
        self._ensure_directory_exists()
        self.load_version_info()
    
    def _ensure_directory_exists(self):
        """Create directory if it doesn't exist"""
        os.makedirs(os.path.dirname(self.version_file), exist_ok=True)
    
    def load_version_info(self):
        """Load version information from file or initialize if new"""
        if os.path.exists(self.version_file):
            with open(self.version_file, 'r') as f:
                self.info = json.load(f)
            print(f"[VERSION] Loaded version info: v{self.info['current_version']}")
        else:
            # Initialize with baseline
            self.info = {
                'current_version': '1.0',
                'created_date': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat(),
                'base_samples': 21752,  # Zenodo dataset size
                'total_samples': 21752,
                'samples_added_total': 0,
                'accuracy_history': [
                    {
                        'version': '1.0',
                        'accuracy': 0.9933,
                        'fpr': 0.0019,
                        'date': datetime.now().isoformat(),
                        'samples': 21752,
                        'notes': 'Baseline model - Zenodo dataset'
                    }
                ],
                'retraining_count': 0,
                'update_history': []
            }
            self._save()
            print(f"[VERSION] Initialized version tracking: v1.0")
    
    def _save(self):
        """Save version info to file"""
        with open(self.version_file, 'w') as f:
            json.dump(self.info, f, indent=2)
    
    def update_version(self, new_accuracy: float, samples_added: int, 
                      fpr: float = None, notes: str = None):
        """
        Update to new model version
        
        Args:
            new_accuracy: Test accuracy of new model
            samples_added: Number of new samples used
            fpr: False positive rate (optional)
            notes: Additional notes about this update
        """
        self.info['retraining_count'] += 1
        
        # Increment version number (1.0 → 1.1 → 1.2, etc.)
        major, minor = self.info['current_version'].split('.')
        new_version = f"{major}.{int(minor) + 1}"
        
        self.info['current_version'] = new_version
        self.info['last_updated'] = datetime.now().isoformat()
        self.info['samples_added_total'] += samples_added
        self.info['total_samples'] = self.info['base_samples'] + self.info['samples_added_total']
        
        # Add to accuracy history
        history_entry = {
            'version': new_version,
            'accuracy': round(new_accuracy, 4),
            'fpr': round(fpr, 4) if fpr else None,
            'date': datetime.now().isoformat(),
            'samples': self.info['total_samples'],
            'samples_added': samples_added,
            'notes': notes or f'Adaptive update #{self.info["retraining_count"]}'
        }
        self.info['accuracy_history'].append(history_entry)
        
        # Add to update history
        update_entry = {
            'version': new_version,
            'date': datetime.now().isoformat(),
            'samples_added': samples_added,
            'accuracy_delta': round(new_accuracy - self.info['accuracy_history'][-2]['accuracy'], 4),
            'notes': notes
        }
        self.info['update_history'].append(update_entry)
        
        self._save()
        
        print(f"[VERSION] ✓ Updated to v{new_version}")
        print(f"          Accuracy: {new_accuracy:.4f}")
        print(f"          Total samples: {self.info['total_samples']:,}")
        print(f"          Retraining cycles: {self.info['retraining_count']}")
    
    def get_current_info(self) -> Dict[str, Any]:
        """Get current version information"""
        latest = self.info['accuracy_history'][-1]
        
        return {
            'version': self.info['current_version'],
            'last_updated': self.info['last_updated'],
            'current_accuracy': latest['accuracy'],
            'current_fpr': latest.get('fpr'),
            'total_samples': self.info['total_samples'],
            'base_samples': self.info['base_samples'],
            'samples_added': self.info['samples_added_total'],
            'retraining_count': self.info['retraining_count']
        }
    
    def get_accuracy_trend(self) -> List[Dict[str, Any]]:
        """Get accuracy evolution over versions"""
        return self.info['accuracy_history']
    
    def get_update_history(self) -> List[Dict[str, Any]]:
        """Get update history"""
        return self.info['update_history']
    
    def print_summary(self):
        """Print a formatted summary of model evolution"""
        print("\n" + "="*80)
        print("MODEL VERSION HISTORY")
        print("="*80)
        
        current = self.get_current_info()
        print(f"\nCurrent Version: v{current['version']}")
        print(f"Last Updated:    {current['last_updated']}")
        print(f"Accuracy:        {current['current_accuracy']:.2%}")
        if current['current_fpr']:
            print(f"FPR:             {current['current_fpr']:.2%}")
        print(f"Total Samples:   {current['total_samples']:,}")
        print(f"Retraining Cycles: {current['retraining_count']}")
        
        print(f"\n{'Version':<10} {'Date':<20} {'Accuracy':<10} {'FPR':<8} {'Samples':<10} {'Notes'}")
        print("-" * 80)
        
        for entry in self.info['accuracy_history']:
            date_str = entry['date'][:10]  # YYYY-MM-DD
            acc_str = f"{entry['accuracy']:.2%}"
            fpr_str = f"{entry['fpr']:.2%}" if entry.get('fpr') else "N/A"
            samples_str = f"{entry['samples']:,}"
            notes = entry.get('notes', '')[:30]
            
            print(f"{entry['version']:<10} {date_str:<20} {acc_str:<10} {fpr_str:<8} {samples_str:<10} {notes}")
        
        print("="*80)
    
    def export_report(self, output_file: str = "adaptive_learning/version_report.txt"):
        """Export detailed version report"""
        with open(output_file, 'w') as f:
            f.write("MODEL VERSION REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            current = self.get_current_info()
            
            f.write("CURRENT STATUS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Version:           v{current['version']}\n")
            f.write(f"Last Updated:      {current['last_updated']}\n")
            f.write(f"Current Accuracy:  {current['current_accuracy']:.4f}\n")
            if current['current_fpr']:
                f.write(f"False Positive Rate: {current['current_fpr']:.4f}\n")
            f.write(f"Total Training Samples: {current['total_samples']:,}\n")
            f.write(f"  - Base (Zenodo):      {current['base_samples']:,}\n")
            f.write(f"  - Added (Adaptive):   {current['samples_added']:,}\n")
            f.write(f"Retraining Cycles:    {current['retraining_count']}\n\n")
            
            f.write("ACCURACY EVOLUTION\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Version':<10} {'Date':<12} {'Accuracy':<10} {'FPR':<10} {'Δ Acc':<10} {'Samples'}\n")
            f.write("-" * 80 + "\n")
            
            prev_acc = None
            for entry in self.info['accuracy_history']:
                delta = ""
                if prev_acc is not None:
                    delta_val = entry['accuracy'] - prev_acc
                    delta = f"{delta_val:+.4f}"
                
                fpr_str = f"{entry['fpr']:.4f}" if entry.get('fpr') else "N/A"
                
                f.write(f"{entry['version']:<10} "
                       f"{entry['date'][:10]:<12} "
                       f"{entry['accuracy']:<10.4f} "
                       f"{fpr_str:<10} "
                       f"{delta:<10} "
                       f"{entry['samples']:,}\n")
                
                if entry.get('notes'):
                    f.write(f"  Note: {entry['notes']}\n")
                
                prev_acc = entry['accuracy']
            
            f.write("\n" + "=" * 80 + "\n")
        
        print(f"[VERSION] Report exported: {output_file}")


# Example usage and testing
if __name__ == "__main__":
    # Initialize version manager
    version_mgr = ModelVersionManager()
    
    # Print current summary
    version_mgr.print_summary()
    
    # Simulate some updates (for testing)
    print("\n[TEST] Simulating version updates...")
    
    # Update 1
    version_mgr.update_version(
        new_accuracy=0.9935,
        samples_added=128,
        fpr=0.0018,
        notes="Added ransomware variants from Dec 2025"
    )
    
    # Update 2
    version_mgr.update_version(
        new_accuracy=0.9941,
        samples_added=87,
        fpr=0.0017,
        notes="Lockbit 3.0 samples integrated"
    )
    
    # Print updated summary
    version_mgr.print_summary()
    
    # Export report
    version_mgr.export_report()
    
    # Show API response format
    print("\n[TEST] API Response Format:")
    api_response = version_mgr.get_current_info()
    print(json.dumps(api_response, indent=2))
