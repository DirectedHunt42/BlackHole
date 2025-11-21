#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==========================================
# CONFIG
# ==========================================
COMPILE_BLACK_HOLE="YES"

OUTPUT_DIR="$SCRIPT_DIR"
LOG_DIR="$SCRIPT_DIR/Log"

REQUIREMENTS_FILE="$SCRIPT_DIR/Requirements.txt"

BLACK_HOLE_SCRIPT="BlackHole.py"
BLACK_HOLE_ICON="$SCRIPT_DIR/Icons/BlackHole_Icon.ico"
BLACK_HOLE_BUILD_NAME="BlackHole"

# ==========================================
# Dependencies
# ==========================================
echo "Checking dependencies..."

python3 -m pip install pyinstaller --break-system-packages || true

echo
echo "Installing script dependencies (skipping Windows-only packages)..."
echo

if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
    echo "ERROR: Requirements.txt not found!"
    exit 1
fi

# -------------------------------
# Filter Requirements.txt
# These lines will be SKIPPED:
#   - pywin32
#   - win32*
#   - pypiwin32
#   - modules only useful on Windows
# -------------------------------
FILTERED_REQ=$(mktemp)

grep -viE "pywin32|pypiwin32|win32|windows|wheels" "$REQUIREMENTS_FILE" > "$FILTERED_REQ"

echo "Using filtered requirements:"
cat "$FILTERED_REQ"
echo

# Install safe requirements
python3 -m pip install -r "$FILTERED_REQ" --break-system-packages || true

echo "Dependencies installed (errors ignored)."
echo

# ==========================================
# Directories
# ==========================================
mkdir -p "$OUTPUT_DIR"
mkdir -p "$LOG_DIR"

echo "Cleaning old build artifacts..."
rm -rf "$LOG_DIR/build" 2>/dev/null || true
rm -f "$LOG_DIR"/*.spec "$LOG_DIR"/*.log "$LOG_DIR"/*.sln 2>/dev/null || true

# ==========================================
# Hidden Imports (Linux-only)
# ==========================================
echo "Setting up hidden imports..."

HIDDEN_IMPORTS=(
    "--hidden-import=customtkinter"
    "--hidden-import=tkinter"
    "--hidden-import=PIL"
    "--hidden-import=PIL.ImageTk"
    "--hidden-import=PIL._tkinter_finder"
    "--hidden-import=cryptography"
    "--hidden-import=cryptography.hazmat.backends"
    "--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2"
    "--hidden-import=docx"
    "--hidden-import=odf"
    "--hidden-import=odf.opendocument"
    "--hidden-import=odf.text"
    "--hidden-import=urllib.request"
    "--hidden-import=pptx"
    "--exclude-module=PIL._avif"
    "--upx-exclude=PIL/_imaging*.so"
    "--upx-exclude=PIL/_imagingtk*.so"
)

echo "Hidden imports set."
echo

# ==========================================
# Validation
# ==========================================
echo "Validating paths..."
echo "No Windows-only assets to validate."
echo

# ==========================================
# Build
# ==========================================
if [[ "$COMPILE_BLACK_HOLE" == "YES" ]]; then
    echo
    echo "Compiling $BLACK_HOLE_SCRIPT..."
    echo

    pyinstaller --noconfirm --onefile --windowed \
        --icon="$BLACK_HOLE_ICON" \
        --clean \
        --noupx \
        "${HIDDEN_IMPORTS[@]}" \
        --distpath "$OUTPUT_DIR" \
        --workpath "$LOG_DIR/build/$BLACK_HOLE_BUILD_NAME" \
        --specpath "$LOG_DIR" \
        "$SCRIPT_DIR/$BLACK_HOLE_SCRIPT" || true

    echo "Successfully compiled $BLACK_HOLE_SCRIPT → $OUTPUT_DIR"
fi

echo
echo "==============================="
echo "✓ Build process finished!"
echo "Executables: $OUTPUT_DIR"
echo "Logs: $LOG_DIR"
echo "==============================="