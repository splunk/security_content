# YAML Formatting & Validation Setup

## Quick Setup

### 1. Install Pre-commit Hook

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install
```

### 2. Install yamlfmt

#### Option A: Using Go

```bash
go install github.com/google/yamlfmt/cmd/yamlfmt@latest
```

#### Option B: Download Standalone Binary

- Download from: <https://github.com/google/yamlfmt/releases>
- Place in your PATH or `~/go/bin/`
- **Alternatively**, use `--yamlfmt-path` flag to specify custom location (see below)

### 3. Install yamllint

```bash
pip install yamllint
```

---

## Usage

### Pre-commit (Automatic)

Pre-commit hook runs automatically when you commit files in `detections/`:

```bash
git add detections/endpoint/my_detection.yml
git commit -m "Add detection"
# yamlfmt runs automatically
```

**Skip hook if needed:**

```bash
git commit --no-verify -m "Skip hooks"
```

### Manual Formatting

Run these from the root directory of `security_content`

```bash
# Format all detection files
yamlfmt detections/

# Format specific file
yamlfmt detections/endpoint/my_detection.yml

# Check what would change (dry run)
yamlfmt -dry detections/
```

### Validation (CI)

```bash
# Validate all detections
python scripts/validate_yaml.py detections/

# Validate specific files
python scripts/validate_yaml.py detections/endpoint/file1.yml detections/cloud/file2.yml

# Validate changed files only
python scripts/validate_yaml.py $(git diff --name-only --diff-filter=ACM develop...HEAD | grep '^detections/.*\.yml$')

# Use custom yamlfmt binary path (when Go is not available)
python scripts/validate_yaml.py --yamlfmt-path /path/to/yamlfmt detections/
```

---

## Troubleshooting

**yamlfmt not found:**

```bash
# Make sure Go bin is in PATH
export PATH="$HOME/go/bin:$PATH"

# Or use absolute path
~/go/bin/yamlfmt detections/

# Or specify path with --yamlfmt-path flag
python scripts/validate_yaml.py --yamlfmt-path /path/to/yamlfmt detections/
```

**Pre-commit hook fails:**

```bash
# Run hook manually to see errors
pre-commit run yamlfmt --files detections/endpoint/file.yml

# Update hooks
pre-commit autoupdate

# Use custom yamlfmt binary in pre-commit
# Edit .pre-commit-config.yaml and add to yamlfmt hook args:
# args: [--yamlfmt-path, /path/to/yamlfmt]
```

**Validation fails in CI:**

- Check the script output for specific errors
- Run locally: `python scripts/validate_yaml.py detections/`
- Ensure files pass both yamllint and yamlfmt --lint

---

## Configuration Files

- `.yamlfmt` - yamlfmt formatting rules (4-space indent, LF line endings)
- `.yamllint` - yamllint validation rules (syntax checks, no duplicate keys)
- `.pre-commit-config.yaml` - Pre-commit hook configuration
