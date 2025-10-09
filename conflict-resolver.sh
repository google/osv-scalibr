#!/bin/bash

# OSV-Scalibr Git Merge Helper
# Automatically resolves secret extractor conflicts during git merges
# Strategy: Accept incoming changes first, then add current changes with new numbers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFLICT_RESOLVER="$SCRIPT_DIR/conflict_resolver.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_usage() {
    echo "OSV-Scalibr Git Merge Helper"
    echo "Automatically resolves secret extractor conflicts during merges"
    echo ""
    echo "Usage: $0 [options] <command>"
    echo ""
    echo "Commands:"
    echo "  merge <branch>      Merge a branch with automatic conflict resolution"
    echo "  resolve             Resolve existing merge conflicts in current state"
    echo ""
    echo "Options:"
    echo "  --dry-run           Show what would be done without making changes"
    echo "  --force             Force merge even if working tree is dirty"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 merge feature/new-secret-extractor"
    echo "  $0 merge origin/main --dry-run"
    echo "  $0 resolve --dry-run"
    echo ""
    echo "Resolution Strategy:"
    echo "  • Incoming changes take priority (accepted first)"
    echo "  • Current branch changes added with new unique numbers"
    echo "  • Protocol buffer files automatically regenerated"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BOLD}=== $1 ===${NC}"
}

check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        return 1
    fi
}

check_working_tree() {
    local force=$1
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        if [[ "$force" != "true" ]]; then
            log_error "Working tree has uncommitted changes"
            log_info "Use --force to proceed anyway, or commit/stash your changes"
            return 1
        else
            log_warning "Proceeding with dirty working tree (--force used)"
        fi
    fi
}

check_merge_in_progress() {
    if [[ -f .git/MERGE_HEAD ]]; then
        return 0  # Merge in progress
    else
        return 1  # No merge in progress
    fi
}

get_conflicted_files() {
    git diff --name-only --diff-filter=U 2>/dev/null || true
}

has_proto_conflicts() {
    local conflicted_files=$(get_conflicted_files)
    if [[ -z "$conflicted_files" ]]; then
        return 1
    fi
    
    echo "$conflicted_files" | grep -E "(scan_result\.proto|secret\.go|scan_result\.pb\.go)" >/dev/null
}

backup_repository_state() {
    local backup_dir="/tmp/osv-scalibr-backup-$(date +%s)-$$"
    mkdir -p "$backup_dir"
    
    # Backup current branch info
    git symbolic-ref --short HEAD 2>/dev/null > "$backup_dir/current_branch.txt" || echo "HEAD" > "$backup_dir/current_branch.txt"
    git rev-parse HEAD > "$backup_dir/current_commit.txt"
    
    # Backup working tree status
    git status --porcelain > "$backup_dir/working_tree_status.txt"
    
    # Backup conflicted files if they exist
    local conflicted_files=$(get_conflicted_files)
    if [[ -n "$conflicted_files" ]]; then
        echo "$conflicted_files" > "$backup_dir/conflicted_files.txt"
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                cp "$file" "$backup_dir/$(basename "$file").conflicted" 2>/dev/null || true
            fi
        done <<< "$conflicted_files"
    fi
    
    echo "$backup_dir"
}

show_conflict_summary() {
    local conflicted_files=$(get_conflicted_files)
    if [[ -z "$conflicted_files" ]]; then
        log_info "No merge conflicts detected"
        return
    fi
    
    log_warning "Merge conflicts detected in:"
    while IFS= read -r file; do
        echo "  📄 $file"
        
        # Show brief conflict info
        if [[ -f "$file" ]]; then
            local conflict_count=$(grep -c "<<<<<<< " "$file" 2>/dev/null || echo "0")
            echo "     └─ $conflict_count conflict(s)"
        fi
    done <<< "$conflicted_files"
}

run_conflict_resolver() {
    local dry_run=$1
    
    if [[ ! -f "$CONFLICT_RESOLVER" ]]; then
        log_error "Conflict resolver not found: $CONFLICT_RESOLVER"
        return 1
    fi
    
    log_info "Running conflict resolver..."
    
    local resolver_args=""
    if [[ "$dry_run" == "true" ]]; then
        resolver_args="--dry-run"
    fi
    
    if python3 "$CONFLICT_RESOLVER" $resolver_args; then
        return 0
    else
        log_error "Conflict resolver failed"
        return 1
    fi
}

cmd_merge() {
    local branch=$1
    local dry_run=$2
    local force=$3
    
    if [[ -z "$branch" ]]; then
        log_error "Branch name is required for merge command"
        print_usage
        return 1
    fi
    
    log_step "Merging branch: $branch"
    
    check_git_repo || return 1
    check_working_tree "$force" || return 1
    
    if check_merge_in_progress; then
        log_error "Merge already in progress. Use 'resolve' command or abort with: git merge --abort"
        return 1
    fi
    
    # Verify branch exists
    if ! git rev-parse --verify "$branch" >/dev/null 2>&1; then
        log_error "Branch '$branch' does not exist"
        return 1
    fi
    
    local current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "detached HEAD")
    log_info "Current branch: $current_branch"
    log_info "Target branch: $branch"
    
    # Create backup
    local backup_dir=$(backup_repository_state)
    log_info "Created backup: $backup_dir"
    
    # Attempt the merge
    log_step "Attempting merge"
    
    if git merge "$branch" --no-commit 2>/dev/null; then
        log_success "Merge completed without conflicts!"
        
        if [[ "$dry_run" == "true" ]]; then
            log_info "Dry run: Aborting clean merge"
            git merge --abort
        else
            log_info "Committing merge..."
            git commit -m "Merge branch '$branch'"
            log_success "Merge committed successfully!"
        fi
        return 0
    fi
    
    # Merge has conflicts - let's resolve them
    log_warning "Merge has conflicts, attempting automatic resolution..."
    
    show_conflict_summary
    
    if has_proto_conflicts; then
        log_info "Found proto-related conflicts that can be auto-resolved"
        
        if run_conflict_resolver "$dry_run"; then
            if [[ "$dry_run" == "true" ]]; then
                log_success "Dry run: All conflicts would be resolved!"
                log_info "Aborting merge..."
                git merge --abort
            else
                # Check if all conflicts are resolved
                local remaining_conflicts=$(get_conflicted_files)
                if [[ -z "$remaining_conflicts" ]]; then
                    log_success "All conflicts resolved automatically!"
                    log_info "Committing merge..."
                    git commit -m "Merge branch '$branch'

Auto-resolved conflicts:
- Protocol buffer field numbering conflicts
- Go import and switch case conflicts
- Regenerated .pb.go files

Resolution strategy: Incoming changes prioritized, current changes added with new numbers."
                    log_success "Merge completed successfully!"
                else
                    log_warning "Some conflicts still need manual resolution:"
                    echo "$remaining_conflicts" | sed 's/^/  - /'
                    log_info "Please resolve manually and then run: git commit"
                fi
            fi
        else
            log_error "Automatic conflict resolution failed"
            log_info "Aborting merge. Manual resolution required."
            git merge --abort
            return 1
        fi
    else
        log_warning "No auto-resolvable proto conflicts found"
        log_info "Manual resolution required for:"
        get_conflicted_files | sed 's/^/  - /'
        log_info "Aborting merge..."
        git merge --abort
        return 1
    fi
}

cmd_resolve() {
    local dry_run=$1
    
    log_step "Resolving existing merge conflicts"
    
    check_git_repo || return 1
    
    if ! check_merge_in_progress; then
        log_error "No merge in progress"
        log_info "Use 'merge <branch>' command to start a merge"
        return 1
    fi
    
    show_conflict_summary
    
    local conflicted_files=$(get_conflicted_files)
    if [[ -z "$conflicted_files" ]]; then
        log_info "No conflicts found. Ready to commit."
        if [[ "$dry_run" != "true" ]]; then
            log_info "Run: git commit"
        fi
        return 0
    fi
    
    if has_proto_conflicts; then
        log_info "Found resolvable conflicts, running resolver..."
        
        if run_conflict_resolver "$dry_run"; then
            local remaining=$(get_conflicted_files)
            if [[ -z "$remaining" ]]; then
                log_success "All conflicts resolved!"
                if [[ "$dry_run" != "true" ]]; then
                    log_info "Ready to commit. Run: git commit"
                fi
            else
                log_warning "Some conflicts remain:"
                echo "$remaining" | sed 's/^/  - /'
            fi
        else
            return 1
        fi
    else
        log_warning "No auto-resolvable conflicts found"
        log_info "Manual resolution required"
        return 1
    fi
}

# Parse command line arguments
COMMAND=""
BRANCH=""
DRY_RUN=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        merge)
            COMMAND="merge"
            BRANCH="$2"
            shift 2
            ;;
        resolve)
            COMMAND="resolve"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            if [[ -z "$COMMAND" ]]; then
                log_error "Unknown command: $1"
            elif [[ "$COMMAND" == "merge" && -z "$BRANCH" ]]; then
                BRANCH="$1"
                shift
            else
                log_error "Unknown option: $1"
            fi
            ;;
    esac
done

# Validate command
if [[ -z "$COMMAND" ]]; then
    log_error "Command is required"
    print_usage
    exit 1
fi

# Execute command
case $COMMAND in
    merge)
        cmd_merge "$BRANCH" "$DRY_RUN" "$FORCE"
        ;;
    resolve)
        cmd_resolve "$DRY_RUN"
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        print_usage
        exit 1
        ;;
esac
