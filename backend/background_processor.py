"""
Background Task Processor for Large ZIP Scans
Implements smart file prioritization and async processing
"""

import asyncio
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class FilePrioritizer:
    """Smart file prioritization for batch scanning."""
    
    # High-risk file patterns (scan these first)
    HIGH_PRIORITY_PATTERNS = [
        'auth', 'login', 'password', 'secret', 'api', 'token',
        'payment', 'credit', 'billing', 'admin', 'config',
        'database', 'db', 'sql', 'user', 'session'
    ]
    
    # Skip these (low value)
    SKIP_PATTERNS = [
        'test', 'spec', '__pycache__', 'node_modules',
        'vendor', 'dist', 'build', '.git', 'mock', 'fixture'
    ]
    
    @classmethod
    def prioritize_files(cls, files: List[Path]) -> List[Path]:
        """
        Sort files by security importance.
        
        Priority order:
        1. High-risk filenames (auth, api, payment, etc.)
        2. Smaller files (faster to scan)
        3. Common vulnerability locations
        """
        
        def get_priority_score(file_path: Path) -> tuple:
            """Return (priority_tier, size) for sorting."""
            
            filename_lower = file_path.name.lower()
            parent_lower = file_path.parent.name.lower()
            
            # Skip low-value files
            if any(skip in filename_lower or skip in str(file_path) for skip in cls.SKIP_PATTERNS):
                return (3, file_path.stat().st_size if file_path.exists() else 999999)
            
            # High priority files
            if any(pattern in filename_lower or pattern in parent_lower for pattern in cls.HIGH_PRIORITY_PATTERNS):
                return (0, file_path.stat().st_size if file_path.exists() else 0)
            
            # Medium priority (controllers, services, models)
            if any(x in filename_lower for x in ['controller', 'service', 'model', 'handler', 'route']):
                return (1, file_path.stat().st_size if file_path.exists() else 0)
            
            # Low priority (everything else)
            return (2, file_path.stat().st_size if file_path.exists() else 0)
        
        # Sort by priority tier first, then by size (smaller first)
        return sorted(files, key=get_priority_score)
    
    @classmethod
    def filter_scannable(cls, files: List[Path], max_files: int = 20) -> List[Path]:
        """Filter and prioritize files for scanning."""
    
        # Only skip truly useless directories
        skip_dirs = ['__pycache__', 'node_modules', '.git', 'venv', 'env', 'dist', 'build']
    
        # Remove only directory-based skips
        filtered = [
            f for f in files 
            if not any(skip_dir in str(f).lower() for skip_dir in skip_dirs)
            and f.exists()
            and f.stat().st_size < 5 * 1024 * 1024  # Skip files > 5MB
        ]
    
        # Prioritize (don't skip files with 'test' or 'vulnerable' in name)
        prioritized = cls.prioritize_files(filtered)
    
        # Limit to max_files
        return prioritized[:max_files]


class BackgroundScanManager:
    """Manages background scanning tasks for large batches."""
    
    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
    
    def create_task(self, scan_id: str, total_files: int) -> Dict[str, Any]:
        """Initialize a background scan task."""
        
        task_data = {
            "scan_id": scan_id,
            "status": "processing",
            "progress": 0,
            "total_files": total_files,
            "files_completed": 0,
            "findings": [],
            "current_file": None,
            "started_at": datetime.now().isoformat(),
            "estimated_completion": None
        }
        
        self.tasks[scan_id] = task_data
        return task_data
    
    def update_progress(self, scan_id: str, files_completed: int, current_file: str = None):
        """Update task progress."""
        
        if scan_id not in self.tasks:
            return
        
        task = self.tasks[scan_id]
        task["files_completed"] = files_completed
        task["progress"] = int((files_completed / task["total_files"]) * 100)
        task["current_file"] = current_file
        
        # Estimate completion time
        if files_completed > 0:
            elapsed = (datetime.now() - datetime.fromisoformat(task["started_at"])).total_seconds()
            avg_time_per_file = elapsed / files_completed
            remaining_files = task["total_files"] - files_completed
            estimated_seconds = int(remaining_files * avg_time_per_file)
            task["estimated_completion"] = f"{estimated_seconds}s remaining"
    
    def add_findings(self, scan_id: str, findings: List[Dict]):
        """Add findings to task."""
        
        if scan_id in self.tasks:
            self.tasks[scan_id]["findings"].extend(findings)
    
    def complete_task(self, scan_id: str, final_result: Dict[str, Any]):
        """Mark task as complete."""
        
        if scan_id in self.tasks:
            self.tasks[scan_id]["status"] = "completed"
            self.tasks[scan_id]["progress"] = 100
            self.tasks[scan_id]["result"] = final_result
            self.tasks[scan_id]["completed_at"] = datetime.now().isoformat()
    
    def fail_task(self, scan_id: str, error: str):
        """Mark task as failed."""
        
        if scan_id in self.tasks:
            self.tasks[scan_id]["status"] = "failed"
            self.tasks[scan_id]["error"] = error
    
    def get_status(self, scan_id: str) -> Dict[str, Any]:
        """Get task status."""
        
        return self.tasks.get(scan_id, {"status": "not_found"})


# Global instance
background_manager = BackgroundScanManager()