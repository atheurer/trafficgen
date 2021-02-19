# TRex install role
The ansible install-trex role downloads, unarchives, and installs trex on your
trafficgen host.

## Configfure Ansible inventory file
Add `trafficgen` host to /etc/ansible/hosts
```
sudo echo "trafficgen" >> /etc/ansible/hosts
```

## Add trafficgen to /etc/hosts
Replace `127.0.0.1` with the actual trafficgen address
```
echo "127.0.0.1 trafficgen" >> /etc/hosts
```

## Make sure you can ssh to trafficgen host
```
ssh trafficgen
```

## Install Trex with ansible role
To install TRex using ansible, run:
```
ansible-playbook install-trex.yaml
```

### Specifying custom options
```
ansible-playbook install-trex.yaml -e trex_ver=v2.82 -e force_install=True -e enable_ssl=False
```
