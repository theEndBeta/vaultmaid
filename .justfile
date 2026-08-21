export LIMA_HOME := "/data/development/.lima"
kilo_name := "kilo.vaultmaid"

# Create lima container w/ kilo code
[group("kilo")]
kcreate name=kilo_name:
  limactl create \
    --name "{{ name }}" \
    .lima.yml

# Stop lima container w/ kilo code
[group("kilo")]
kstart name=kilo_name:
  limactl start \
    --progress \
    --mount .:w \
    "{{ name }}"

# Stop lima container w/ kilo code
[group("kilo")]
kstop name=kilo_name:
  limactl stop "{{ name }}"

# Shell into lima container w/ kilo code
[group("kilo")]
kshell name=kilo_name:
  limactl shell \
    --reconnect \
    --start \
    --shell /usr/bin/fish \
    "{{ name }}"

# Delete lima container w/ kilo code
[group("kilo")]
kdel name=kilo_name:
  limactl delete "{{ name }}"

# requires lima >=2.1
# --sync . \
