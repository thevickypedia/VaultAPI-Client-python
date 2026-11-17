#!/bin/zsh
TABLE=$1
AUTO_DELETE=true
[[ "$2" == "false" ]] && AUTO_DELETE=false
VAULT_CLIENT=${VAULT_CLIENT:-vaultapi-client}
#filename=$(${VAULT_CLIENT} --get-secret $2 --table $1 --env true)
filename=$(${VAULT_CLIENT} --table ${TABLE} --env true)
if [[ -n "$filename" && -f "$filename" ]]; then
  source ${filename}
  count=$(($(wc -l < "${filename}")))
  echo "${count} secrets from table '${TABLE}' has been loaded to environment variables"
  echo "Auto delete set to: $AUTO_DELETE"
  if [[ "$AUTO_DELETE" == "true" ]]; then
      rm -- "$filename"
  fi
fi
