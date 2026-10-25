#!/usr/bin/env bash
# upgrade.sh: install the newest earlier release's example, seed state, then swap in this tree's example the way
# DEPLOY.md's upgrade does and check the state survives. Needs full git history with tags, and validate.sh's env.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./lib.sh

AUTH_REGISTRY="${AUTH_REGISTRY:-registry.gitlab.com/dunn.dev/othala}"
CUR="${AUTH_VERSION:-latest}"
PREV=$(git tag --merged HEAD -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | grep -vxF "${CI_COMMIT_TAG:-}" | head -1)
[[ -n "$PREV" ]] || { echo "  ✗ no earlier release tag in history (shallow clone?)"; exit 1; }
echo "=== othala upgrade: $PREV -> $CUR ==="

RC=0
check() { if [[ "$2" == "$3" ]]; then echo "  ✓ $1"; else echo "  ✗ $1 (want '$3', got '$2')"; RC=1; fi; }
export AUTH_REGISTRY COMPOSE_FILE=compose.yml:compose.e2e.yml

git show "$PREV:deploy/example/compose.yml" > compose.yml
git show "$PREV:deploy/example/postgres-init.sh" > postgres-init.sh
chmod +x postgres-init.sh
registry_login
(umask 077 && gen_secrets "$PREV" > secrets.env) || { echo "  ✗ gen-secrets failed"; exit 1; }
load_env
AUTH_VERSION="$PREV" up_and_wait

# State an upgrade must keep: an identity, an API session, an OIDC grant with a refresh token.
PW='upgrade-seed-Passw0rd-7431'
read -r SUB TOKEN <<<"$(cat <<JS | node_in othala
const J={'Content-Type':'application/json'};
const post=async(u,b)=>(await fetch(u,{method:'POST',headers:J,body:JSON.stringify(b)})).json();
(async()=>{
  const i=await post('http://kratos:4434/admin/identities',{schema_id:'family',traits:{username:'up.member',email:'up.member@${OTHALA_APEX}',displayName:'Up Member'},metadata_admin:{groups:['grafana-access']},credentials:{password:{config:{password:'$PW'}}}});
  const f=await (await fetch('http://kratos:4433/self-service/login/api')).json();
  const s=await post('http://kratos:4433/self-service/login?flow='+f.id,{method:'password',identifier:'up.member@${OTHALA_APEX}',password:'$PW'});
  process.stdout.write(i.id+' '+s.session_token);process.exit(0);
})().catch(()=>process.exit(1));
JS
)"
[[ -n "${TOKEN:-}" ]] || { echo "  ✗ seeding failed"; exit 1; }
REFRESH=$(AUTH_VERSION="$CUR" run_dance "$SUB" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
[[ -n "$REFRESH" ]] || { echo "  ✗ no refresh token from the seed dance"; exit 1; }
echo "  seeded identity, session and refresh token on $PREV"

# DEPLOY.md: new example, new secret keys, then the restart-rules command.
cp ../deploy/example/compose.yml ../deploy/example/postgres-init.sh .
gen_secrets "$CUR" | while IFS= read -r l; do grep -q "^${l%%=*}=" secrets.env || echo "$l" >> secrets.env; done
load_env
export AUTH_VERSION="$CUR"
timeout 300 docker compose up -d --force-recreate render kratos hydra othala caddy || { echo "  ✗ recreate failed"; RC=1; }
up_and_wait

probe() { printf '%s' "$1" | node_in othala; }
check "session survives" "$(probe "fetch('http://kratos:4433/sessions/whoami',{headers:{'X-Session-Token':'$TOKEN'}}).then(async r=>{const j=await r.json();process.stdout.write(r.status+' '+(j.identity||{}).id);process.exit(0)}).catch(()=>process.exit(1))")" "200 $SUB"
check "refresh grant survives" "$(probe "fetch('http://hydra:4444/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Forwarded-Proto':'https',Authorization:'Basic '+Buffer.from('grafana:${GRAFANA_CLIENT_SECRET}').toString('base64')},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:'$REFRESH'})}).then(async r=>{const j=await r.json();process.stdout.write(r.status+' '+!!j.access_token);process.exit(0)}).catch(()=>process.exit(1))")" "200 true"
check "consent session survives" "$(probe "fetch('http://${HYDRA_ADMIN_BIND_HOST}:4445/admin/oauth2/auth/sessions/consent?subject=$SUB').then(async r=>{process.stdout.write(String((await r.json()).length));process.exit(0)}).catch(()=>process.exit(1))")" "1"
check "issuer unchanged" "$(probe "fetch('http://hydra:4444/.well-known/openid-configuration').then(async r=>{process.stdout.write((await r.json()).issuer);process.exit(0)}).catch(()=>process.exit(1))")" "${OTHALA_PUBLIC_URL}/"

bash ./smoke.sh || RC=1
if [[ $RC -ne 0 ]]; then
    for svc in kratos hydra othala caddy; do echo "--- lab-$svc ---"; podman logs --tail=60 "lab-$svc" 2>&1 || true; done
fi
docker compose down -v --remove-orphans || true
[[ $RC -eq 0 ]] && echo "=== upgrade PASSED ===" || echo "=== upgrade FAILED ==="
exit "$RC"
