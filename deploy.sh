#!/usr/bin/env bash
#
# First-time deploy / update for Aegis behind Caddy on a Linux VM.
# Run on the VM as a sudo-capable NON-root user. Idempotent: safe to re-run for updates.
#
#   REPO_URL=https://github.com/JESX301/aegis-grc.git ./deploy.sh
#
# Requires a .env file in the app dir (copied from .env.example) with DOMAIN + AEGIS_SECRET_KEY.

set -euo pipefail

REPO_URL="${REPO_URL:?set REPO_URL to your git remote}"
APP_DIR="${APP_DIR:-$HOME/aegis-grc}"
BRANCH="${BRANCH:-main}"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

echo "==> 1/5 Ensure Docker is installed"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  echo "Docker installed. Log out/in (or run: newgrp docker) and re-run this script."
  exit 0
fi

echo "==> 2/5 Clone or update the repo at $APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
else
  git -C "$APP_DIR" fetch --all --tags
  git -C "$APP_DIR" reset --hard "origin/$BRANCH"
fi
cd "$APP_DIR"

echo "==> 3/5 Require .env (never committed)"
if [ ! -f .env ]; then
  echo "ERROR: no .env. Copy .env.example to .env, set DOMAIN + AEGIS_SECRET_KEY, then chmod 600 .env." >&2
  exit 1
fi
chmod 600 .env

echo "==> 4/5 Build and bring up (app + Caddy)"
$COMPOSE up -d --build
$COMPOSE ps

echo "==> 5/5 Verify"
sleep 5
DOMAIN_VALUE="$(grep -E '^DOMAIN=' .env | cut -d= -f2-)"
echo "Hitting https://${DOMAIN_VALUE}/healthz (Caddy issues the TLS cert on first request)..."
curl -fsS "https://${DOMAIN_VALUE}/healthz" || echo "Health check not green yet — check: $COMPOSE logs --tail=50"
echo "Done. Update later by re-running this script (git reset --hard + rebuild)."
