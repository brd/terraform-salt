## About
This script allows terraform to connect to a SaltStack master and
generate keys, prior to launching the hosts so that the keys can be
injected into cloud-init.

## Example
* Create a unix account on the SaltStack master called `terraform-salt`.
* Allow it to be used to auth on the master:
```
external_auth:      
  pam:
    terraform-salt:
      - '@wheel'
```
* Update the `pam_user` & `pam_passwd` variables in `salt_generate_key.py`
* Enable the REST CherryPy API:
```
rest_cherrypy:
  port: 8080
  ssl_crt: /usr/local/etc/ssl/corp/cert.pem
  ssl_key: /usr/local/etc/ssl/corp/key.pem
```

* Restart the SaltStack Master
* Restart the SaltStack API
* In terraform add a external data source for creating VMs:
```
data "external" "salt-key" {
  program = ["python", "salt_generate_key.py"]
  query = {
    host = var.hostname
    site = var.site
  }
}
```
* In terraform add a provisioner to the VMs as part of the vm resource
for cleaning up:
```
  provisioner "local-exec" {
    command = "python salt_generate_key.py -d ${self.name_label}"
    when = destroy
  }
```
* In terraform add a data block for the template file that cloud-init
will use.  Note that this supports overrides for specific hostnames.
```
data "template_file" "cloudinit" {
  template = fileexists( join("", ["cloud-config-", replace(var.hostname, "/\\d+$/", ""), ".tpl"] ) ) ? join("", [ file("cloud-config.tpl"), file( join("", ["cloud-config-", replace(var.hostname, "/\\d+$/", ""), ".tpl"] ) ) ] ) : file("cloud-config.tpl")
  vars = {
    hostname = var.hostname
    site     = var.site
    salt_private_key = data.external.salt-key.result.salt_private_key
    salt_public_key  = data.external.salt-key.result.salt_public_key
  }
}
```
* Create the cloud-init template file in the top level of the terraform
directory: `cloud-config.tpl`:
```
#cloud-config
hostname: ${hostname}.${site}.internal
salt_minion:
  conf:
    log_level_logfile: info
    startup_states: highstate
  grains:
    site: ${site}
  public_key: |
${salt_public_key}
  private_key: |
${salt_private_key}
```
