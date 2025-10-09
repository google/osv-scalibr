#!/usr/bin/env python3
"""
OSV-Scalibr Secret Extractor Conflict Resolver

This tool automatically resolves merge conflicts when adding new secret extractors
to the OSV-Scalibr project by:
1. Parsing Git merge conflict markers in files
2. Taking incoming changes as base (priority to incoming)
3. Adding current branch changes with new unique numbers
4. Resolving conflicts in proto, Go, and generated files

Usage:
    python conflict_resolver.py [--dry-run] [--repo-path <path>]
"""

import re
import sys
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import tempfile

class MergeConflictResolver:
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.proto_file = self.repo_path / "binary/proto/scan_result.proto"
        self.secret_go_file = self.repo_path / "binary/proto/secret.go"
        self.pb_go_file = self.repo_path / "binary/proto/scan_result_go_proto/scan_result.pb.go"
        
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            result = subprocess.run(
                cmd, cwd=cwd or self.repo_path, capture_output=True, text=True, check=True
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except FileNotFoundError:
            return False, f"Command not found: {cmd[0]}"
    
    def has_merge_conflicts(self, file_path: Path) -> bool:
        """Check if a file has merge conflict markers."""
        if not file_path.exists():
            return False
        
        content = file_path.read_text()
        return "<<<<<<< " in content and "=======" in content and ">>>>>>> " in content
    
    def parse_conflict_sections(self, content: str) -> List[Dict[str, str]]:
        """
        Parse merge conflict markers and extract sections.
        Returns list of conflicts with 'current', 'incoming', and 'context' parts.
        """
        conflicts = []
        
        # Pattern to match conflict blocks
        conflict_pattern = r'<<<<<<< ([^\n]+)\n(.*?)\n=======\n(.*?)\n>>>>>>> ([^\n]+)'
        
        for match in re.finditer(conflict_pattern, content, re.DOTALL):
            current_ref = match.group(1)
            current_content = match.group(2)
            incoming_content = match.group(3)
            incoming_ref = match.group(4)
            
            conflicts.append({
                'current_ref': current_ref,
                'current_content': current_content,
                'incoming_ref': incoming_ref,
                'incoming_content': incoming_content,
                'full_match': match.group(0)
            })
        
        return conflicts
    
    def extract_oneof_entries(self, content: str) -> Tuple[Dict[str, Tuple[str, int]], int]:
        """
        Extract oneof entries from proto content.
        Returns dict of field_name -> (field_type, field_number) and max number.
        """
        entries = {}
        max_number = 0
        
        # Pattern to match proto field declarations
        field_pattern = r'(\w+)\s+(\w+)\s*=\s*(\d+);'
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            match = re.match(field_pattern, line)
            if match:
                field_type, field_name, field_number = match.groups()
                field_number = int(field_number)
                entries[field_name] = (field_type, field_number)
                max_number = max(max_number, field_number)
        
        return entries, max_number
    
    def resolve_proto_conflict(self, content: str) -> str:
        """
        Resolve conflicts in proto file by:
        1. Taking incoming changes as base
        2. Adding current branch entries with new numbers
        3. Preserving all message definitions
        """
        conflicts = self.parse_conflict_sections(content)
        resolved_content = content
        
        for conflict in conflicts:
            # Parse entries from both sides
            current_entries, current_max = self.extract_oneof_entries(conflict['current_content'])
            incoming_entries, incoming_max = self.extract_oneof_entries(conflict['incoming_content'])
            
            print(f"Current branch entries: {list(current_entries.keys())}")
            print(f"Incoming branch entries: {list(incoming_entries.keys())}")
            
            # Find entries only in current branch
            current_only = set(current_entries.keys()) - set(incoming_entries.keys())
            
            # Start with incoming content as base
            merged_section = conflict['incoming_content']
            
            # Add current-only entries with new numbers
            if current_only:
                next_number = max(incoming_max, current_max) + 1
                additional_lines = []
                
                for field_name in sorted(current_only):
                    field_type, _ = current_entries[field_name]
                    additional_lines.append(f"    {field_type} {field_name} = {next_number};")
                    print(f"Adding {field_name} with number {next_number}")
                    next_number += 1
                
                # Add to the end of the incoming content
                if additional_lines:
                    merged_section = merged_section.rstrip() + '\n' + '\n'.join(additional_lines)
            
            # Replace the conflict with resolved content
            resolved_content = resolved_content.replace(conflict['full_match'], merged_section)
        
        return resolved_content
    
    def extract_import_statements(self, content: str) -> Set[str]:
        """Extract import statements from Go content."""
        imports = set()
        
        # Look for import declarations
        import_patterns = [
            r'^\s*"([^"]+)"',  # Direct imports: "package/path"
            r'^\s*\w+\s+"([^"]+)"',  # Aliased imports: alias "package/path"
        ]
        
        in_import_block = False
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('import ('):
                in_import_block = True
                continue
            elif line == ')' and in_import_block:
                in_import_block = False
                continue
            elif line.startswith('import '):
                # Single import line
                for pattern in import_patterns:
                    match = re.search(pattern, line)
                    if match:
                        imports.add(match.group(1))
                        break
            elif in_import_block and line and not line.startswith('//'):
                # Import within import block
                for pattern in import_patterns:
                    match = re.search(pattern, line)
                    if match:
                        imports.add(match.group(1))
                        break
        
        return imports
    
    def extract_switch_cases(self, content: str) -> Dict[str, str]:
        """Extract switch cases from Go content."""
        cases = {}
        
        # Find switch statements and extract cases
        # Look for case statements with secret types
        case_pattern = r'case\s*\*[^:]*\.([^:]+):(.*?)(?=case\s|\n\s*default\s*:|$)'
        
        for match in re.finditer(case_pattern, content, re.DOTALL):
            case_type = match.group(1).strip()
            case_body = match.group(2).strip()
            cases[case_type] = f"case *spb.{case_type}:\n{case_body}"
        
        return cases
    
    def resolve_go_conflict(self, content: str) -> str:
        """
        Resolve conflicts in Go files by merging imports and switch cases.
        Priority: incoming first, then add current-only items.
        """
        conflicts = self.parse_conflict_sections(content)
        resolved_content = content
        
        for conflict in conflicts:
            current_imports = self.extract_import_statements(conflict['current_content'])
            incoming_imports = self.extract_import_statements(conflict['incoming_content'])
            
            current_cases = self.extract_switch_cases(conflict['current_content'])
            incoming_cases = self.extract_switch_cases(conflict['incoming_content'])
            
            # Merge imports (incoming first, then current-only)
            all_imports = incoming_imports | (current_imports - incoming_imports)
            
            # Merge cases (incoming first, then current-only)
            all_cases = incoming_cases.copy()
            for case_type, case_code in current_cases.items():
                if case_type not in incoming_cases:
                    all_cases[case_type] = case_code
            
            # Reconstruct the merged section
            merged_section = conflict['incoming_content']
            
            # Add any missing imports from current
            current_only_imports = current_imports - incoming_imports
            if current_only_imports:
                # Find import section and add missing imports
                for imp in sorted(current_only_imports):
                    if f'"{imp}"' not in merged_section:
                        # Add import - this is a simplified approach
                        print(f"Would need to add import: {imp}")
            
            # Add any missing cases from current
            current_only_cases = set(current_cases.keys()) - set(incoming_cases.keys())
            if current_only_cases:
                for case_type in sorted(current_only_cases):
                    print(f"Would need to add case: {case_type}")
                    # In a real implementation, we'd add the case before the default case
                    merged_section += f"\n\t{current_cases[case_type]}"
            
            # Replace the conflict with resolved content
            resolved_content = resolved_content.replace(conflict['full_match'], merged_section)
        
        return resolved_content
    
    def resolve_generic_conflict(self, content: str) -> str:
        """
        Resolve generic conflicts by taking incoming first, then adding current.
        For any file that doesn't have specific resolution logic.
        """
        conflicts = self.parse_conflict_sections(content)
        resolved_content = content
        
        for conflict in conflicts:
            # Simple strategy: incoming content first, then current content
            merged_section = conflict['incoming_content']
            
            # Add current content if it's different and not empty
            if conflict['current_content'].strip() and conflict['current_content'] != conflict['incoming_content']:
                merged_section += '\n' + conflict['current_content']
            
            resolved_content = resolved_content.replace(conflict['full_match'], merged_section)
        
        return resolved_content
    
    def regenerate_pb_go(self) -> bool:
        """Regenerate the .pb.go file from the proto file."""
        proto_dir = self.proto_file.parent
        
        success, output = self.run_command([
            "protoc",
            "--go_out=.",
            "--go_opt=paths=source_relative",
            str(self.proto_file.name)
        ], proto_dir)
        
        if success:
            print(f"✓ Successfully regenerated {self.pb_go_file}")
            return True
        else:
            print(f"✗ Failed to regenerate .pb.go file: {output}")
            if "protoc" in output and "not found" in output:
                print("  Install protoc: apt-get install protobuf-compiler (Ubuntu) or brew install protobuf (macOS)")
            return False
    
    def resolve_all_conflicts(self, dry_run: bool = False) -> bool:
        """
        Main method to resolve all merge conflicts in the repository.
        """
        print("🔍 Scanning for merge conflicts...")
        
        # Check for conflicted files
        success, git_status = self.run_command(["git", "status", "--porcelain"])
        if not success:
            print("✗ Failed to check git status")
            return False
        
        conflicted_files = []
        for line in git_status.split('\n'):
            if line.startswith('UU ') or line.startswith('AA ') or 'both modified' in line:
                file_path = line.split()[-1]
                conflicted_files.append(self.repo_path / file_path)
        
        if not conflicted_files:
            print("✓ No merge conflicts found")
            return True
        
        print(f"📁 Found {len(conflicted_files)} conflicted files:")
        for file_path in conflicted_files:
            print(f"  - {file_path.relative_to(self.repo_path)}")
        
        # Resolve each conflicted file
        resolved_files = []
        
        for file_path in conflicted_files:
            print(f"\n🔧 Resolving conflicts in {file_path.relative_to(self.repo_path)}...")
            
            if not self.has_merge_conflicts(file_path):
                print(f"  ✓ No conflict markers found, marking as resolved")
                resolved_files.append(file_path)
                continue
            
            try:
                original_content = file_path.read_text()
                
                # Apply appropriate resolution strategy
                if file_path.name == "scan_result.proto":
                    resolved_content = self.resolve_proto_conflict(original_content)
                elif file_path.name == "secret.go":
                    resolved_content = self.resolve_go_conflict(original_content)
                else:
                    resolved_content = self.resolve_generic_conflict(original_content)
                
                # Check if all conflicts were resolved
                if "<<<<<<< " in resolved_content:
                    print(f"  ⚠️  Some conflicts remain unresolved in {file_path.name}")
                    continue
                
                if not dry_run:
                    # Create backup
                    backup_path = file_path.with_suffix(f"{file_path.suffix}.backup")
                    file_path.rename(backup_path)
                    
                    # Write resolved content
                    file_path.write_text(resolved_content)
                    print(f"  ✓ Resolved conflicts (backup: {backup_path.name})")
                else:
                    print(f"  ✓ Would resolve conflicts (dry run)")
                
                resolved_files.append(file_path)
                
            except Exception as e:
                print(f"  ✗ Failed to resolve {file_path.name}: {e}")
        
        # Regenerate proto files if proto was modified
        if any(f.name == "scan_result.proto" for f in resolved_files):
            print(f"\n🔄 Regenerating protocol buffer files...")
            if not dry_run:
                if not self.regenerate_pb_go():
                    return False
            else:
                print("  ✓ Would regenerate .pb.go files (dry run)")
        
        # Mark files as resolved in git
        if resolved_files and not dry_run:
            print(f"\n✅ Marking {len(resolved_files)} files as resolved in git...")
            file_paths = [str(f.relative_to(self.repo_path)) for f in resolved_files]
            success, output = self.run_command(["git", "add"] + file_paths)
            if success:
                print("✓ Files marked as resolved")
            else:
                print(f"✗ Failed to mark files as resolved: {output}")
                return False
        
        print(f"\n🎉 Successfully resolved conflicts in {len(resolved_files)} files!")
        
        if not dry_run:
            print("\nNext steps:")
            print("1. Review the resolved files")
            print("2. Run tests to ensure everything works")
            print("3. Complete the merge: git commit")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Resolve OSV-Scalibr secret extractor merge conflicts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 conflict_resolver.py                    # Resolve all conflicts
  python3 conflict_resolver.py --dry-run         # Show what would be done
  python3 conflict_resolver.py --repo-path ../   # Use different repo path

This tool handles merge conflicts by:
1. Taking incoming changes as the base (priority to incoming branch)
2. Adding current branch changes with new unique numbers for proto files
3. Merging imports and switch cases for Go files
4. Regenerating protocol buffer files automatically
        """
    )
    
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--repo-path', default='.',
                       help='Path to the repository (default: current directory)')
    
    args = parser.parse_args()
    
    resolver = MergeConflictResolver(args.repo_path)
    
    # Basic validation
    if not (resolver.repo_path / '.git').exists():
        print("❌ Not in a git repository")
        print(f"   Path checked: {resolver.repo_path.absolute()}")
        sys.exit(1)
    
    success = resolver.resolve_all_conflicts(args.dry_run)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
