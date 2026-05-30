#!/bin/bash
# Upgrade the chiefstaker program on the currently-configured Solana cluster.
#
# By default this pulls the verifiable .so artifact from the latest successful
# CI run on master and deploys it as an upgrade to the production program ID
# (--program-id is passed explicitly so a missing flag can't accidentally
# create a brand-new program at a random address).
#
# A local .so can be supplied with --so to skip the CI download (useful when
# resuming a partially-failed deploy with the same artifact).
#
# Usage:
#   ./scripts/deploy-program.sh                       # latest master artifact
#   ./scripts/deploy-program.sh --run-id 26644748323  # specific CI run
#   ./scripts/deploy-program.sh --so /tmp/chiefstaker.so
#   ./scripts/deploy-program.sh --priority-fee 100000

set -euo pipefail

PROGRAM_ID="3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr"
REPO="KarpelesLab/chiefstaker"
WORKFLOW="CI"
ARTIFACT_NAME="chiefstaker-verifiable"
ARTIFACT_FILE="chiefstaker.so"
DEFAULT_PRIORITY_FEE=50000

AGAVE_LOCAL="$HOME/.local/share/solana/install/active_release/bin"
if [ -x "/pkg/main/net-p2p.agave.core/bin/solana" ]; then
    SOLANA_CLI="/pkg/main/net-p2p.agave.core/bin/solana"
elif [ -x "$AGAVE_LOCAL/solana" ]; then
    SOLANA_CLI="$AGAVE_LOCAL/solana"
else
    SOLANA_CLI="solana"
fi

LOCAL_SO=""
RUN_ID=""
PRIORITY_FEE="$DEFAULT_PRIORITY_FEE"

usage() {
    cat <<EOF
Usage: $0 [options]
  --so <path>           Deploy from a local .so file (skips CI download)
  --run-id <id>         Use a specific GitHub Actions run ID for the artifact
  --priority-fee <N>    Compute unit price, micro-lamports / CU (default: $DEFAULT_PRIORITY_FEE)
  -h, --help            Show this help

With no options: downloads the artifact from the latest successful $WORKFLOW
run on master and upgrades program $PROGRAM_ID on the configured cluster.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --so)             LOCAL_SO="$2";       shift 2 ;;
        --run-id)         RUN_ID="$2";         shift 2 ;;
        --priority-fee)   PRIORITY_FEE="$2";   shift 2 ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# --- Resolve the .so file ------------------------------------------------------
if [ -n "$LOCAL_SO" ]; then
    PROGRAM_SO="$LOCAL_SO"
    SOURCE_DESC="local file"
else
    if ! command -v gh >/dev/null 2>&1; then
        echo "Error: 'gh' CLI not found. Install it, or pass --so <path>." >&2
        exit 1
    fi

    if [ -z "$RUN_ID" ]; then
        RUN_ID=$(gh run list -R "$REPO" --workflow "$WORKFLOW" --branch master \
                    --status success --limit 1 --json databaseId --jq '.[0].databaseId')
        if [ -z "$RUN_ID" ]; then
            echo "Error: no successful $WORKFLOW run found on master." >&2
            exit 1
        fi
    fi

    DL_DIR=$(mktemp -d -t chiefstaker-deploy-XXXXXX)
    trap "rm -rf '$DL_DIR'" EXIT
    echo "Downloading $ARTIFACT_NAME from $REPO run $RUN_ID..."
    gh run download "$RUN_ID" -R "$REPO" -n "$ARTIFACT_NAME" -D "$DL_DIR"
    PROGRAM_SO="$DL_DIR/$ARTIFACT_FILE"
    SOURCE_DESC="CI run $RUN_ID"
fi

if [ ! -f "$PROGRAM_SO" ]; then
    echo "Error: program file not found: $PROGRAM_SO" >&2
    exit 1
fi

# --- Pre-flight: confirm upgrade authority matches the configured keypair -----
LOCAL_AUTH=$("$SOLANA_CLI" address)
CHAIN_AUTH=$("$SOLANA_CLI" program show "$PROGRAM_ID" | awk '/^Authority:/ {print $2}')
RPC_URL=$("$SOLANA_CLI" config get | awk '/^RPC URL:/ {print $3}')
SO_SIZE=$(wc -c < "$PROGRAM_SO" | tr -d ' ')

echo ""
echo "=== Deploy plan ==="
echo "Program ID:    $PROGRAM_ID"
echo "Source:        $SOURCE_DESC"
echo "Binary:        $PROGRAM_SO ($SO_SIZE bytes)"
echo "Cluster:       $RPC_URL"
echo "Local key:     $LOCAL_AUTH"
echo "On-chain auth: $CHAIN_AUTH"
echo "Priority fee:  $PRIORITY_FEE micro-lamports / CU"
echo ""

if [ "$LOCAL_AUTH" != "$CHAIN_AUTH" ]; then
    echo "Error: local keypair is NOT the upgrade authority. Aborting." >&2
    exit 1
fi

# --- Deploy --------------------------------------------------------------------
"$SOLANA_CLI" program deploy \
    --program-id "$PROGRAM_ID" \
    --with-compute-unit-price "$PRIORITY_FEE" \
    "$PROGRAM_SO"

echo ""
echo "Deployment complete!"
