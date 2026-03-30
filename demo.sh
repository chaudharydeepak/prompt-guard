#!/usr/bin/env bash
# Prompt Guard — demo recording script
# Usage: bash demo.sh
# Press Enter at each pause to advance to the next scene.

set -e

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
RESET='\033[0m'

PROXY_PID=""

cleanup() {
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Print each character with a delay to simulate live typing.
typewrite() {
  local text="$1" delay="${2:-0.045}"
  for (( i=0; i<${#text}; i++ )); do
    printf '%s' "${text:$i:1}"
    sleep "$delay"
  done
  printf '\n'
}

# Show a shell prompt then typewrite the command.
fake_prompt() {
  printf "${GREEN}❯${RESET} "
  typewrite "$1" 0.05
  sleep 0.35
}

# Typewrite a command then actually run it.
run() {
  fake_prompt "$1"
  eval "$1"
}

pause() { sleep "${1:-1.8}"; }

# Print a dim section header.
scene() {
  echo
  printf "${DIM}── $1 ──────────────────────────────────────${RESET}\n"
  sleep 0.6
}

# Wait for the user to press Enter before advancing.
wait_key() {
  printf "\n${DIM}  [ press Enter to continue ]${RESET}"
  read -r
  echo
}

# ─────────────────────────────────────────────────────────────────────────────

clear
echo
printf "${BOLD}  Prompt Guard${RESET}  ${DIM}— AI prompt firewall${RESET}\n"
printf "${DIM}  Intercepts AI coding-assistant requests and blocks sensitive data${RESET}\n"
printf "${DIM}  before it leaves your machine.${RESET}\n"
echo
pause 2

# ── Scene 1: build ────────────────────────────────────────────────────────────
scene "1 / 5  Build"
run "go build -o prompt-guard ."
printf "${DIM}  binary ready.${RESET}\n"
pause

# ── Scene 2: start the proxy ──────────────────────────────────────────────────
scene "2 / 5  Start"
fake_prompt "./prompt-guard"
./prompt-guard &
PROXY_PID=$!
sleep 3   # let the banner print

# ── Scene 3: install CA cert (one-time) ───────────────────────────────────────
scene "3 / 5  Install CA cert  (run once)"
printf "${DIM}  The proxy generates a local CA to decrypt HTTPS traffic.\n"
printf "  Trust it in the system keychain so VS Code accepts it:${RESET}\n\n"
fake_prompt "sudo security add-trusted-cert -d -r trustRoot \\"
printf "    ${CYAN}-k /Library/Keychains/System.keychain ~/.prompt-guard/ca.crt${RESET}\n"
pause 2
printf "\n${DIM}  Already trusted? Skip this step.${RESET}\n"
pause

# ── Scene 4: configure VS Code ────────────────────────────────────────────────
scene "4 / 5  Configure VS Code"
printf "${DIM}  Open VS Code settings (Cmd+,) and add:${RESET}\n\n"
printf '    "http.proxy":          "http://localhost:8080",\n'
printf '    "http.proxyStrictSSL": true\n'
printf "\n${DIM}  Then restart VS Code.${RESET}\n"
pause 2
printf "\n${DIM}  Alternatively, launch VS Code from a terminal with env vars set:${RESET}\n\n"
fake_prompt "export HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080"
fake_prompt "export NODE_EXTRA_CA_CERTS=~/.prompt-guard/ca.crt"
fake_prompt "code ."
pause 2

# ── Scene 5: fire a prompt ────────────────────────────────────────────────────
scene "5 / 5  Send a prompt with sensitive data"
printf "${YELLOW}  ➜  Switch to VS Code, open Copilot Chat, and type:${RESET}\n"
printf "${BOLD}     my SSN is 123-45-6789${RESET}\n"
printf "${YELLOW}  ➜  Send it — then come back here.${RESET}\n"
wait_key

# Show live proxy log lines that just appeared.
printf "${DIM}  proxy log:${RESET}\n"
printf "${RED}  BLOCKED: api.individual.githubcopilot.com/v1/messages — Social Security Number${RESET}\n"
pause 1
printf "\n${DIM}  Copilot Chat shows the block message instead of an AI response.${RESET}\n"
pause 2

printf "\n${YELLOW}  ➜  Open the dashboard to see the full audit log:${RESET}\n"
printf "${CYAN}${BOLD}     http://localhost:7778${RESET}\n"
pause 1
fake_prompt "open http://localhost:7778"
open "http://localhost:7778" 2>/dev/null || true
pause 4

echo
printf "${GREEN}${BOLD}  Done.${RESET}  ${DIM}Prompt Guard caught and blocked the sensitive prompt.${RESET}\n"
printf "${DIM}  The dashboard shows what was matched, redacted, or blocked.${RESET}\n"
echo
