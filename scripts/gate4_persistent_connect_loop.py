#!/usr/bin/python3
"""Controlled long-lived connect loop for persistent Gate 4 failure tests."""
from __future__ import annotations
import argparse, errno, json, socket, time
from pathlib import Path
def main()->None:
 parser=argparse.ArgumentParser();parser.add_argument("--attempts",type=int,default=20);parser.add_argument("--delay-ms",type=int,default=25);parser.add_argument("--state",type=Path,required=True);args=parser.parse_args();results=[]
 for attempt in range(args.attempts):
  channel=socket.socket()
  try:channel.connect(("1.1.1.1",80));effect="CONNECTED"
  except OSError as error:effect=errno.errorcode.get(error.errno,str(error.errno))
  finally:channel.close()
  results.append(effect);args.state.write_text(json.dumps({"attempts_completed":len(results),"results":results})+"\n");time.sleep(args.delay_ms/1000)
if __name__=="__main__":main()
