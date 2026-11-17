TABLE=$1
AUTO_DELETE=true
[[ "$2" == "false" ]] && AUTO_DELETE=false
#filename=$(vaultapi-client --get-secret $2 --table $1 --env true)
filename=$(vaultapi-client --table ${TABLE} --env true)
source ${filename}
count=$(($(wc -l < "${filename}")))
echo "${count} secrets from table '${TABLE}' has been loaded to environment variables"
echo "Auto delete set to: $AUTO_DELETE"
if [[ "$AUTO_DELETE" == "true" ]]; then
    rm -- "$filename"
fi
