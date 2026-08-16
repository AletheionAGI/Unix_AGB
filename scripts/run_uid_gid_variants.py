#!/usr/bin/env python3
"""Privileged UID/GID allowlist variants (opt-in laboratory test)."""
import json, os, pwd, shutil, subprocess, tempfile, time
from pathlib import Path

def main():
    if os.geteuid() != 0 or os.getenv("AGB_RUN_UID_GID_VARIANTS") != "1":
        print(json.dumps({"status":"skipped","reason":"requires root and AGB_RUN_UID_GID_VARIANTS=1"}, indent=2)); return
    tag = str(os.getpid()); users = [f"agbvar-a-{tag}", f"agbvar-b-{tag}"]; group = f"agbvar-g-{tag}"
    subprocess.run(["groupadd", "--system", group], check=True)
    try:
        gid = pwd.getpwnam("root").pw_gid
        subprocess.run(["useradd", "--system", "--no-create-home", "--gid", group, users[0]], check=True)
        subprocess.run(["useradd", "--system", "--no-create-home", "--gid", group, users[1]], check=True)
        accounts = [pwd.getpwnam(u) for u in users]; gid = accounts[0].pw_gid
        root = Path(__file__).resolve().parents[1]; binary = root / "target/debug/agb-admin-server"
        if not binary.exists(): subprocess.run(["cargo","build","--quiet","--bin","agb-admin-server"], cwd=root, check=True)
        with tempfile.TemporaryDirectory(prefix="agb-uid-gid-variants-") as d:
            base=Path(d); base.chmod(0o755); lab=base/"server"; shutil.copy2(binary,lab); lab.chmod(0o755)
            client=base/"client.py"; shutil.copy2(root/"scripts/admin_request.py",client); client.chmod(0o755)
            results=[]; audits={}
            for name, env_extra in (("uid_gid", {"AGB_ADMIN_UIDS":str(accounts[0].pw_uid),"AGB_ADMIN_GIDS":str(gid)}),("gid_only", {"AGB_ADMIN_GIDS":str(gid)}),("uid_only", {"AGB_ADMIN_UIDS":str(accounts[0].pw_uid)})):
                sock=base/(name+".sock"); audit=base/(name+".audit"); cache=base/(name+".cache")
                env={**os.environ,"AGB_ADMIN_TOKEN":"variant-token","AGB_ADMIN_AUTHZ_REVISION":"lab-authz-v1",**env_extra}; p=subprocess.Popen([str(lab),str(sock),str(cache),str(audit)],env=env)
                try:
                    for _ in range(100):
                        if sock.exists(): break
                        time.sleep(.02)
                    sock.chmod(0o666)
                    for acct in accounts:
                        response=json.loads(subprocess.check_output(["runuser","-u",acct.pw_name,"--","python3",str(client),str(sock),"variant-token"],text=True))
                        results.append({"case":name,"uid":acct.pw_uid,"gid":acct.pw_gid,"response":response})
                    p.terminate(); p.wait(timeout=3); sock.unlink(missing_ok=True)
                    env["AGB_ADMIN_AUTHZ_REVISION"] = "lab-authz-v2"
                    p=subprocess.Popen([str(lab),str(sock),str(cache),str(audit)],env=env)
                    for _ in range(100):
                        if sock.exists(): break
                        time.sleep(.02)
                    sock.chmod(0o666)
                    for acct in accounts:
                        restart_response=json.loads(subprocess.check_output(["runuser","-u",acct.pw_name,"--","python3",str(client),str(sock),"variant-token"],text=True))
                        results.append({"case":name,"restart":True,"uid":acct.pw_uid,"gid":acct.pw_gid,"response":restart_response})
                    audits[name]=[json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
                finally: p.terminate(); p.wait(timeout=3)
            if any(len(events) < 4 or [event.get("authorization_revision") for event in events] != ["lab-authz-v1", "lab-authz-v1", "lab-authz-v2", "lab-authz-v2"] for events in audits.values()): raise SystemExit("audit log missing variant events or authorization revision")
            print(json.dumps({"status":"passed","shared_gid":gid,"results":results,"audit_events":audits},indent=2))
    finally:
        for u in users: subprocess.run(["userdel",u],check=False)
        subprocess.run(["groupdel",group],check=False)
if __name__ == "__main__": main()
