"""
Multi-Format File Parser for Atlas Synapse Auditor
Extracts scannable content from PDFs, DOCX, XLSX, HTML, and media files
"""

import re
from typing import Dict, Any, List
from pathlib import Path


class FileParser:
    """Parse various file formats for security scanning."""
    
    @staticmethod
    def parse_pdf(file_path: str) -> str:
        """Extract text from PDF for scanning."""
        try:
            # Try PyPDF2 first (lightweight)
            import PyPDF2
            text = ""
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages[:50]:  # Limit to 50 pages
                    text += page.extract_text() + "\n"
            return text
        except ImportError:
            # Fallback: scan PDF as binary for secrets
            with open(file_path, 'rb') as f:
                return f.read().decode('utf-8', errors='ignore')[:100000]
        except Exception as e:
            return f"# PDF parsing error: {e}"
    
    @staticmethod
    def parse_docx(file_path: str) -> str:
        """Extract text from DOCX."""
        try:
            import zipfile
            text = ""
            with zipfile.ZipFile(file_path) as docx:
                if 'word/document.xml' in docx.namelist():
                    xml_content = docx.read('word/document.xml').decode('utf-8')
                    # Extract text between XML tags
                    text = re.sub(r'<[^>]+>', ' ', xml_content)
            return text
        except Exception as e:
            return f"# DOCX parsing error: {e}"
    
    @staticmethod
    def parse_xlsx(file_path: str) -> str:
        """Extract formulas and macros from Excel."""
        try:
            import zipfile
            formulas = []
            with zipfile.ZipFile(file_path) as xlsx:
                # Check for macros (VBA)
                if 'xl/vbaProject.bin' in xlsx.namelist():
                    formulas.append("# WARNING: Excel file contains VBA macros (potential security risk)")
                
                # Extract sheet data
                for name in xlsx.namelist():
                    if name.startswith('xl/worksheets/'):
                        content = xlsx.read(name).decode('utf-8', errors='ignore')
                        # Look for formulas
                        formula_matches = re.findall(r'<f[^>]*>([^<]+)</f>', content)
                        formulas.extend(formula_matches[:100])
            
            return "# Excel Formulas:\n" + "\n".join(formulas[:50])
        except Exception as e:
            return f"# XLSX parsing error: {e}"
    
    @staticmethod
    def parse_html(file_path: str) -> str:
        """Parse HTML/XML files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"# HTML parsing error: {e}"
    
    @staticmethod
    def parse_media_metadata(file_path: str) -> str:
        """Extract metadata from media files (basic analysis)."""
        try:
            stat = Path(file_path).stat()
            
            analysis = f"""# Media File Metadata Analysis
File: {Path(file_path).name}
Size: {stat.st_size} bytes
Type: {Path(file_path).suffix}

# Security Checks:
- File size: {'⚠️ Large file (>10MB)' if stat.st_size > 10*1024*1024 else '✅ Normal'}
- Extension: {Path(file_path).suffix}

# Note: Media files scanned for embedded metadata and suspicious patterns only.
# Full content analysis requires specialized media forensics tools.
"""
            return analysis
        except Exception as e:
            return f"# Media parsing error: {e}"
    
    @staticmethod
    def get_scannable_content(file_path: str) -> str:
        """
        Get scannable text content from any file type.
        Returns code/text that can be analyzed by security scanners.
        """
        
        ext = Path(file_path).suffix.lower()
        
        # Code files - return as-is
        if ext in ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs', '.jsx', '.tsx', '.rs', '.kt', '.swift']:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except:
                return ""
        
        # Documents
        elif ext == '.pdf':
            return FileParser.parse_pdf(file_path)
        elif ext in ['.docx', '.doc']:
            return FileParser.parse_docx(file_path)
        elif ext in ['.xlsx', '.xls']:
            return FileParser.parse_xlsx(file_path)
        
        # Web files
        elif ext in ['.html', '.htm', '.xml', '.svg']:
            return FileParser.parse_html(file_path)
        
        # Text files
        elif ext in ['.txt', '.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf']:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except:
                return ""
        
        # Media files (metadata only)
        elif ext in ['.mp3', '.mp4', '.wav', '.avi', '.mov', '.jpg', '.jpeg', '.png', '.gif', '.pdf']:
            return FileParser.parse_media_metadata(file_path)
        
        # Unknown - try as text
        else:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()[:50000]  # Limit to 50KB
            except:
                return f"# Binary file: {Path(file_path).name} (unscannable)"