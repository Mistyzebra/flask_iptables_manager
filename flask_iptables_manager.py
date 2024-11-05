#!/usr/bin/env python3
# coding:utf-8
# @Author: yumu
# @Date:   2020-08-22
# @Email:   yumusb@foxmail.com
# @Last Modified by:   Mistyzebra
# @Last Modified time: 2024-11-05

from flask import Flask, request, render_template
import sys, os, subprocess, json, re

if len(sys.argv) != 3:
    exit("usage: python %s (int)[port] (string)[path]" % (sys.argv[0]))

FLASK_PORT = int(sys.argv[1])  # 运行的端口

if not subprocess.check_output(
    f"iptables -nL | grep dpt:{FLASK_PORT}".encode(), shell=True
).strip():
    subprocess.run(
        f"iptables -I INPUT -p tcp --dport {FLASK_PORT} -j ACCEPT -m comment --comment 'Flask验证服务端口，默认规则'".encode(),
        shell=True,
    )

FLASK_PATH = f"/{sys.argv[2].strip()}"  # 运行的route
app = Flask(__name__)


@app.route("/")
def index():
    return "Hello, World!"


@app.route(FLASK_PATH)
def hello_index():
    ip = request.remote_addr
    existed = subprocess.check_output(
        f"iptables -nL | grep '{ip}'".encode(), shell=True
    ).decode()
    if not existed.strip():
        subprocess.run(
            f"iptables -A INPUT -s {ip} -j ACCEPT -m comment --comment '`date '+%Y_%m_%d %H:%M:%S'`'".encode(),
            shell=True,
        )
        return f"{ip} add success"
    else:
        return f"{ip} existed"


@app.route(FLASK_PATH + "/admin/")
def admin():
    a = subprocess.check_output(
        "iptables -L INPUT -v -n --line-number".encode(), shell=True
    ).decode()
    a = a.split("\n")[2:]
    b = subprocess.check_output(
        "iptables -nL INPUT | head -1".encode(), shell=True
    ).decode()
    return render_template("admin.html", iptables=a, default=b)


@app.route(FLASK_PATH + "/admin/del/", methods=["POST"])
def admin_del():
    id = request.form["id"]
    result = subprocess.run(
        f"iptables -D INPUT {id}".encode(), shell=True, capture_output=True
    )
    data = {"status": str(result.returncode), "result": result.stdout.decode()}
    return json.dumps(data)


@app.route(FLASK_PATH + "/admin/DelAllPortRules/", methods=["POST"])
def DelAllPortRules():
    sshport = subprocess.check_output(
        "netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (\".*:\",\"\",$4);print $4}'".encode(),
        shell=True,
    ).decode()
    result = subprocess.run(
        f"for i in $(iptables -nL INPUT --line-numbers | grep -v \"dpt:{FLASK_PORT}\" | grep -v \"dpt:{sshport}\" | grep 'dpt:' | awk -F ' ' '{{print $1}}' | tac); do iptables -D INPUT $i ; done".encode(),
        shell=True,
        capture_output=True,
    )
    data = {"status": str(result.returncode), "result": result.stdout.decode()}
    return json.dumps(data)


@app.route(FLASK_PATH + "/admin/DelAllIpRules/", methods=["POST"])
def DelAllIpRules():
    result = subprocess.run(
        f"for i in $(iptables -nL INPUT --line-numbers | grep -v \"0.0.0.0/0            0.0.0.0/0\" | grep -E \"[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}\.[0-9]{{1,3}}\" |  grep -v '{request.remote_addr}' | awk -F ' ' '{{print $1}}' | tac); do iptables -D INPUT $i ; done".encode(),
        shell=True,
        capture_output=True,
    )
    data = {"status": str(result.returncode), "result": result.stdout.decode()}
    return json.dumps(data)


@app.route(FLASK_PATH + "/admin/add/", methods=["POST"])
def admin_add():
    param = request.form["p"]
    param = re.sub("[^\d\.\/]+", ",", param)
    params = param.split(",")
    base_commands = []
    pattern = re.compile(r"^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2]\d|3[0-2])){0,1}$")
    for p in params:
        p = p.strip()
        if p:
            if "." not in p and int(p) in range(1, 65535):
                existed = subprocess.check_output(
                    f"iptables -L INPUT -n | grep \"dpt:{p} \" ".encode(), shell=True
                ).decode()
                if not existed.strip():
                    base_commands.append(
                        f"iptables -I INPUT -p tcp --dport {int(p)} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\""
                    )
            elif pattern.match(p):
                existed = subprocess.check_output(
                    f"iptables -L INPUT -n | grep '{p}'".encode(), shell=True
                ).decode()
                if not existed.strip():
                    base_commands.append(
                        f"iptables -A INPUT -s {p} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\""
                    )
    if base_commands:
        result = subprocess.run(
            ";".join(base_commands).encode(), shell=True, capture_output=True
        )
        data = {
            "status": str(result.returncode),
            "result": result.stdout.decode(),
            "command": ";".join(base_commands),
        }
    else:
        data = {"status": "999", "result": "参数有问题"}
    return json.dumps(data)


app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
