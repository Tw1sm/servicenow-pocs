# ServiceNoew Cred Dump POC
POC script to authenticate to a ServiceNow instance and retrive cleartext secret data from the discovery_credentials table by backdooring the default CredentialTestAjax script include. Requires a significant level of permission in ServiceNow.

```
$ uv run now_dumpcred_poc.py -h
usage: now_dumpcred_poc.py [-h] -i INSTANCE_URL -u USER [-p PASSWORD] -s SYS_ID

POC backdoor of CredentialTestAjax script include to retrieve cleartext discovery_credentials in AJAX requests. Usage: python dumpcred_poc.py -i https://dev12345.service-now.com -u admin -p <password> -s <sys_id>

options:
  -h, --help            show this help message and exit
  -i INSTANCE_URL, --instance-url INSTANCE_URL
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
                        Prompted if omitted
  -s SYS_ID, --sys-id SYS_ID
```