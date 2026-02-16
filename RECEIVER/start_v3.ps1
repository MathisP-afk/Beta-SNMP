python "$PSScriptRoot/snmp_trap_receiver_v3.py" `
    -s 10.204.0.119 `
    -u Alleria_W `
    --auth-password Vereesa_W `
    --priv-password Windrunner `
    -a "https://10.204.0.158:8000" `
    -k "GDT98WBtTizrMUQcxEGD1Aw7YNzGL0qiywklUfD2i4PRNng4LWE018jYjrOCgKCm" `
    -e 80004fb8054d534917e0c200 `
    -i "Ethernet 2" `
    --poll-interval 60
