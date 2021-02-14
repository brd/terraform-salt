#!/usr/bin/env python

import argparse
import datetime
import json
import os
import requests
import subprocess
import sys

salt_master = 'salt.internal'
salt_port = 8080
salt_url = 'https://' + salt_master + ':' + str(salt_port) + '/'
ca_cert = '/usr/local/etc/ssl/corp/ca-bundle-chain.pem'
base_domain = 'internal'
terraform_salt_cache = '/usr/local/etc/terraform/salt'
# Create a local unix account and change these to match
pam_user = 'terraform-salt'
pam_passwd = 'foo'

log_file = '/tmp/salt_manage_key.log'
http_headers = { 'Accept': 'application/json' }
input = {}
j = {}

def log_message(msg):
  with open(log_file, 'a') as f:
    date = datetime.datetime.now()
    f.write(date.strftime("%Y/%m/%d %H:%M:%S") + ' ' + msg + '\n')

def login():
  # Login to the API
  # {"return": [{"token": "5adf36aef2770ee886828937350a8dbd5eb95d51", "expire": 1603861472.3164086, "start": 1603818272.316407, "user": "terraform-salt", "eauth": "pam", "perms": ["@wheel"]}]}%
  login_http_params = { 'username': pam_user, 'password': pam_passwd, 'eauth': 'pam' }
  login_url = 'https://' + salt_master + ':' + str(salt_port) + '/login'
  login = requests.post(login_url, data = login_http_params, headers = http_headers, verify = ca_cert)
  if login.status_code != requests.codes.ok:
    print(f'Error logging in to: {login_url}')
    login.raise_for_status()

  output = login.json()
  if 'token' not in output['return'][0]:
    print(f'Login token not present in output')
    sys.exit(4)
  log_message('login(): login to saltstack successful, got token')
  return output["return"][0]["token"]

def pad(rsa):
  nrsa = ""
  for line in rsa.splitlines():
    nrsa = nrsa + '    ' + line + '\n'
  return nrsa

def create_minion(minion, j):
  log_message('create_minion(): addming minion to salt master')
  gen_http_params = { 'client': 'wheel', 'fun': 'key.gen_accept', 'id_': minion + '.' + base_domain}
  gen = requests.post(salt_url, data = gen_http_params, headers = http_headers, verify = ca_cert)
  if gen.status_code != requests.codes.ok:
    log_message('Error logging in to: ' + gen_url)
    print(f'Error logging in to: {gen_url}')
    gen.raise_for_status()

  gen_results = gen.json()['return'][0]['data']
  if 'success' in gen_results and gen_results['success'] == True:
    log_message('create_minion(): success: ' + minion)
    j['salt_private_key'] = pad(gen_results['return']['priv'])
    j['salt_public_key'] = pad(gen_results['return']['pub'])
    # store keypair
    if not os.path.isdir(terraform_salt_cache):
      log_message('create_minion(): Error: path: ' + terraform_salt_cache + ', does not exist')
      sys.exit(8)
    if not os.path.isdir(terraform_salt_cache + '/' + minion):
      os.mkdir(terraform_salt_cache + '/' + minion, mode=0o770)
      os.chown(terraform_salt_cache + '/' + minion, -1, 983)
      os.chmod(terraform_salt_cache + '/' + minion, 0o770)
    with open(terraform_salt_cache + '/' + minion + '/pub', 'w') as f:
      f.write(gen_results['return']['pub'])
    os.chmod(terraform_salt_cache + '/' + minion + '/pub', 0o660)
    os.chown(terraform_salt_cache + '/' + minion + '/pub', -1, 983)
    with open(terraform_salt_cache + '/' + minion + '/private', 'w') as f:
      f.write(gen_results['return']['priv'])
    os.chmod(terraform_salt_cache + '/' + minion + '/private', 0o660)
    os.chown(terraform_salt_cache + '/' + minion + '/private', -1, 983)
  else:
    print(f'Error creating keypair: {minion}: {gen_results}')
    log_message('create_minion(): failure: ' + minion)
    log_message(gen_results)

def delete_minion(token, minion):
  log_message('delete_minion(): deleting minion from salt master')
  delete_http_params = { 'client': 'wheel', 'fun': 'key.delete', 'match': minion + '.' + base_domain}
  http_headers['X-Auth-Token'] = token
  delete = requests.post(salt_url, data = delete_http_params, headers = http_headers, verify = ca_cert)
  if delete.status_code != requests.codes.ok:
    print(f'Error connecting to: {salt_url}')
    delete.raise_for_status()
  delete_results = delete.json()['return'][0]['data']
  if 'success' in delete_results and delete_results['success'] == True:
    # Delete the cached keypair
    if os.path.exists(terraform_salt_cache + '/' + minion):
      log_message("delete_minion(): deleting minion's cached keypair")
      if os.path.isfile(terraform_salt_cache + '/' + minion + '/private'):
        os.remove(terraform_salt_cache + '/' + minion + '/private')
      if os.path.isfile(terraform_salt_cache + '/' + minion + '/pub'):
        os.remove(terraform_salt_cache + '/' + minion + '/pub')
      os.rmdir(terraform_salt_cache + '/' + minion)

def check_terraform_state():
  # Check if keypairs exist that should not
  files = []
  for entry in os.listdir(terraform_salt_cache):
    if not os.path.isfile(terraform_salt_cache + '/' + entry):
      files.append(entry)

  check = subprocess.run(['terraform', 'show', '-json'], capture_output=True, text=True)
  if check.returncode != 0:
    print(f'error calling terraform: {check.stdout} {check.stderr}')
    log_message('check_terraform_state(): Error calling terraform' + check.stdout + ' ' + check.stderr)
  # Parse json output and if the minion is not found, check local keypair store and nuke
  # {
  #     "values": {
  #         "root_module": {
  #             "child_modules": [
  #                 {
  #                     "resources": [
  #                         {
  #                             "type": "xenorchestra_vm",
  #                             "values": {
  #                                 "name_label": "host.site",
  existing = []
  j = json.loads(check.stdout)
  if "values" in j and "root_module" in j["values"] and "child_modules" in j["values"]["root_module"]:
    for module in j["values"]["root_module"]["child_modules"]:
      if "resources" in module:
        for res in module["resources"]:
          if "type" in res and res["type"] == "xenorchestra_vm":
            if "values" in res and "name_label" in res["values"]:
              if res["values"]["name_label"] in files:
                files.remove(res["values"]["name_label"])

  if len(files) > 0:
    token = login()
  for minion in files:
    log_message('check_terraform_state(): minion not found in terraform state: ' + minion + ', removing')
    delete_minion(token, minion)

def read_file(file):
  if os.path.isfile(file):
    try:
      with open(file, 'r') as f:
        return pad("".join(f.readlines()))
    except Exception as e:
      log_message('read_file(): error opening and reading: ' + file + ' ' + str(e))
  else:
    log_message('read_file(): file does not exist: ' + file)

def read_keypair(minion, j):
  j['salt_public_key']  = read_file(terraform_salt_cache + '/' + minion + '/pub')
  j['salt_private_key'] = read_file(terraform_salt_cache + '/' + minion + '/private')


# Check for command line flags
parser = argparse.ArgumentParser()
parser.add_argument('-d', metavar='minion', help='minion to remove cached keypair and from the salt master')
args = parser.parse_args()
if (args.d):
  log_message('-d, minion: ' + args.d)
  delete_minion(login(), args.d)
  sys.exit(0)
else:
  # Import stdin variables
  for line in sys.stdin:
    input = json.loads(line)
  minion = input['host'] + '.' + input['site']

token = login()

# Check for an existing key
# name_match
name_http_params = { 'client': 'wheel', 'fun': 'key.name_match', 'match': minion + '*'}
http_headers['X-Auth-Token'] = token
name = requests.post(salt_url, data = name_http_params, headers = http_headers, verify = ca_cert)
if name.status_code != requests.codes.ok:
  print(f'Error connecting to: {salt_url}')
  name.raise_for_status()

name_results = name.json()['return'][0]['data']
if 'success' in name_results and name_results['success'] == True:
  if 'return' in name_results and 'minions' in name_results['return']:
    if len(name_results['return']['minions']) == 1:
      read_keypair(minion, j)
    else:
      log_message('Too many minions matched: ' + len(name_results['return']['minions']))
      sys.exit(9)
  else:
    create_minion(minion, j)
else:
  log_message('Error: searching for minion')
  sys.exit(10)

# Publish to terraform
print(json.dumps(j))
