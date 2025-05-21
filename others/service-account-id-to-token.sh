#!/usr/bin/env bash

SERVICE_ACCOUNT_ID=36e073e4-fa88-4fd1-a0af-73fd825c7cbf
AUD=https://identity-qe.staples.com/am/oauth2/access_token
SCOPE=fr:idc:proxy-connect:*

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines fail if any command fails, not just the last one.
set -o pipefail

# --- Configuration & Input Validation ---

# Check required tools
command -v jose >/dev/null 2>&1 || { echo >&2 "Error: 'jose' command not found. Please install jose-util."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "Error: 'curl' command not found."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo >&2 "Error: 'openssl' command not found."; exit 1; }
command -v date >/dev/null 2>&1 || { echo >&2 "Error: 'date' command not found."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo >&2 "Warning: 'jq' command not found. Output will not be pretty-printed."; }


# Get SERVICE_ACCOUNT_ID from environment or argument 1
if [[ -z "${SERVICE_ACCOUNT_ID:-}" && -z "${1:-}" ]]; then
  echo >&2 "Error: SERVICE_ACCOUNT_ID is not set."
  echo >&2 "Usage: export SERVICE_ACCOUNT_ID=<id> && $0"
  echo >&2 "   or: $0 <service_account_id> <audience_url> <scope>"
  exit 1
fi
SA_ID="${SERVICE_ACCOUNT_ID:-${1}}" # Use env var if set, else use arg 1

# Get AUD (Audience URL) from environment or argument 2
if [[ -z "${AUD:-}" && -z "${2:-}" ]]; then
  echo >&2 "Error: AUD (Audience URL) is not set."
  echo >&2 "Usage: export AUD=<url> && $0"
  echo >&2 "   or: $0 <service_account_id> <audience_url> <scope>"
  exit 1
fi
AUDIENCE_URL="${AUD:-${2}}" # Use env var if set, else use arg 2

# Get SCOPE from environment or argument 3
if [[ -z "${SCOPE:-}" && -z "${3:-}" ]]; then
  echo >&2 "Error: SCOPE is not set."
  echo >&2 "Usage: export SCOPE=<scope> && $0"
  echo >&2 "   or: $0 <service_account_id> <audience_url> <scope>"
  exit 1
fi
REQUEST_SCOPE="${SCOPE:-${3}}" # Use env var if set, else use arg 3

# Key file path (adjust if needed)
KEY_FILE="key.jwk"
PAYLOAD_FILE="payload.json"
JWT_FILE="jwt.txt"

# Check if key file exists
if [[ ! -f "$KEY_FILE" ]]; then
    echo >&2 "Error: Private key file '$KEY_FILE' not found in the current directory."
    exit 1
fi

echo "--- Configuration ---"
echo "Service Account ID (iss/sub): $SA_ID"
echo "Audience (aud):               $AUDIENCE_URL"
echo "Scope:                        $REQUEST_SCOPE"
echo "Private Key File:             $KEY_FILE"
echo "---------------------"
echo

# --- Step 2: Create and sign a JWT ---

echo "Step 2: Creating and signing JWT..."

# Calculate Expiration Time (15 minutes = 899 seconds)
# Note: date -u ensures UTC time is used for the timestamp
EXP=$(($(date -u +%s) + 899))
echo "Calculated Expiry (exp): $EXP"

# Generate Unique JWT ID (JTI)
JTI=$(openssl rand -base64 16)
echo "Generated JWT ID (jti):  $JTI"

# Create payload.json file
# Use printf for potentially better handling of special characters than echo -n
printf '{
    "iss":"%s",
    "sub":"%s",
    "aud":"%s",
    "exp":%s,
    "jti":"%s"
}' "$SA_ID" "$SA_ID" "$AUDIENCE_URL" "$EXP" "$JTI" > "$PAYLOAD_FILE"

echo "Created $PAYLOAD_FILE"
# Optional: uncomment to view payload
# echo "--- Payload Content ---"
# cat $PAYLOAD_FILE
# echo "---------------------"

# Sign the JWT using jose-util
# -I: Input payload file
# -k: Private key JWK file
# -s '{"alg":"RS256"}': Set signing header explicitly (important!)
# -c: Compact serialization (standard JWT format)
# -o: Output file
echo "Signing JWT using '$KEY_FILE'..."
jose jws sig -I "$PAYLOAD_FILE" -k "$KEY_FILE" -s '{"alg":"RS256"}' -c -o "$JWT_FILE"

if [[ ! -f "$JWT_FILE" || ! -s "$JWT_FILE" ]]; then
    echo >&2 "Error: Failed to create JWT file '$JWT_FILE'."
    rm -f "$PAYLOAD_FILE" # Clean up payload file on error
    exit 1
fi

echo "Signed JWT created: $JWT_FILE"
echo

# --- Step 3: Get an access token using the JWT ---

echo "Step 3: Requesting access token..."

# Read JWT assertion from file
ASSERTION=$(< "$JWT_FILE")

# --- Prepare components for printing the curl command ---
# Values for simple --data arguments
CURL_DATA_CLIENT_ID="client_id=service-account"
CURL_DATA_GRANT_TYPE="grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"

# For --data-urlencode arguments, the value needs shell escaping for printing if it contains special characters.
# The JWT assertion itself is typically base64url encoded and safe, but the scope might have spaces.
# We'll apply printf %q to the assertion value just in case for robustness in printing.
CURL_ESCAPED_ASSERTION_CONTENT=$(printf '%q' "$ASSERTION")
CURL_DATA_URLENCODE_ASSERTION_ARG="assertion=${CURL_ESCAPED_ASSERTION_CONTENT}"

CURL_ESCAPED_SCOPE_CONTENT="$REQUEST_SCOPE"
CURL_DATA_URLENCODE_SCOPE_ARG="scope=${CURL_ESCAPED_SCOPE_CONTENT}"

# Construct the printable command string
PRINTABLE_CURL_COMMAND=$(printf 'curl -sS --request POST %s \\\n  --data "%s" \\\n  --data "%s" \\\n  --data-urlencode "%s" \\\n  --data-urlencode "%s"' \
    "$AUDIENCE_URL" \
    "$CURL_DATA_CLIENT_ID" \
    "$CURL_DATA_GRANT_TYPE" \
    "$CURL_DATA_URLENCODE_ASSERTION_ARG" \
    "$CURL_DATA_URLENCODE_SCOPE_ARG"
)

echo "Executing command:"
echo -e "$PRINTABLE_CURL_COMMAND" # -e interprets backslashes for newline
echo # Extra newline for separation before execution output

CURL_EXIT_CODE=$? # Capture exit code immediately

# Check if curl command succeeded and got a response
if [[ "$CURL_EXIT_CODE" -ne 0 ]]; then
    echo >&2 "Error: curl command failed with exit code $CURL_EXIT_CODE."
    # Cleanup intermediate files
    rm -f "$PAYLOAD_FILE" "$JWT_FILE"
    exit 1
fi
exit 0