#!/usr/bin/env python3
# coding:utf-8
from flask import Flask, request, render_template, jsonify, abort
import sys
import os
import subprocess
import re

if len(sys.argv) != 3:
    sys.exit(f"Usage: python {sys.argv[0]} (int)[port] (string)[path]")

FLASK_PORT = int(sys.argv[1])
FLASK_PATH = f'/{sys.argv[2].strip()}'

app = Flask(__name__)

def run_command(command):
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return process.returncode, process.stdout.strip()

def is_port_open(port):
    return len(run_command(f"iptables -nL | grep dpt:{port}")[1]) > 0

def is_ip_rule_exists(ip):
    return len(run_command(f"iptables -nL | grep '{ip}'")[1]) > 0

def add_ip_rule(ip):
    run_command(f"iptables -A INPUT -s {ip} -j ACCEPT -m comment --comment 'Added on {run_command('date +%Y_%m_%d_%H:%M:%S')[1]}'")

def validate_ip(ip):
    pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2]\d|3[0-2]))?$')
    return pattern.match(ip) is not None

if not is_port_open(FLASK_PORT):
    run_command(f'iptables -I INPUT -p tcp --dport {FLASK_PORT} -j ACCEPT -m comment --comment "Flask service port"')

@app.route('/')
def index():
    return 'Hello, World!'

@app.route(FLASK_PATH)
def hello_index():
    ip = request.remote_addr
    if not is_ip_rule_exists(ip):
        add_ip_rule(ip)
        return f"{ip} add success"
    else:
        return f"{ip} existed"

@app.route(f"{FLASK_PATH}/admin/")
def admin():
    iptables_output = run_command("iptables -L INPUT -v -n --line-number")[1].split("\n")[2:]
    default_rule = run_command("iptables -nL INPUT | head -1")[1]
    return render_template('admin.html', iptables=iptables_output, default=default_rule)

@app.route(f"{FLASK_PATH}/admin/del/", methods=['POST'])
def admin_del():
    rule_id = request.form.get('id')
    if not rule_id.isdigit():
        return abort(400, "Invalid rule ID")
    status, result = run_command(f"iptables -D INPUT {rule_id}")
    return jsonify({'status': str(status), 'result': result})

@app.route(f"{FLASK_PATH}/admin/DelAllPortRules/", methods=['POST'])
def del_all_port_rules():
    ssh_port = run_command("netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (\".*:\",\"\",$4);print $4}'")[1]
    status, result = run_command(f"for i in $(iptables -nL INPUT --line-numbers | grep -v 'dpt:{FLASK_PORT}' | grep -v 'dpt:{ssh_port}' | grep 'dpt:' | awk -F ' ' '{{print $1}}' | tac); do iptables -D INPUT $i; done")
    return jsonify({'status': str(status), 'result': result})

@app.route(f"{FLASK_PATH}/admin/DelAllIpRules/", methods=['POST'])
def del_all_ip_rules():
    remote_ip = request.remote_addr
    status, result = run_command(f"for i in $(iptables -nL INPUT --line-numbers | grep -v '0.0.0.0/0            0.0.0.0/0' | grep -E '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | grep -v '{remote_ip}' | awk -F ' ' '{{print $1}}' | tac); do iptables -D INPUT $i; done")
    return jsonify({'status': str(status), 'result': result})

@app.route(f"{FLASK_PATH}/admin/add/", methods=['POST'])
def admin_add():
    param = request.form.get('p', '')
    param = re.sub(r'[^\d\.\/]+', ',', param)
    params = param.split(",")
    base_commands = []

    for p in params:
        p = p.strip()
        if not p:
            continue
        if p.isdigit() and 1 <= int(p) <= 65535:
            if not is_port_open(int(p)):
                base_commands.append(f"iptables -I INPUT -p tcp --dport {p} -j ACCEPT -m comment --comment 'Added on {run_command('date +%Y_%m_%d_%H:%M:%S')[1]}'")
        elif validate_ip(p):
            if not is_ip_rule_exists(p):
                base_commands.append(f"iptables -A INPUT -s {p} -j ACCEPT -m comment --comment 'Added on {run_command('date +%Y_%m_%d_%H:%M:%S')[1]}'")

    if base_commands:
        status, result = run_command(";".join(base_commands))
        data = {'status': str(status), 'result': result, 'command': ";".join(base_commands)}
    else:
        data = {'status': '999', 'result': "Invalid parameters"}

    return jsonify(data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=True)
