apt install python3
apt install python3-venv
chmod +x /opt/dns/myenv/bin/*
source /opt/dns/myenv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cp /opt/dns/*.service /etc/systemd/system




mkdir -p /etc/systemd/system/docker.service.d

vi /etc/systemd/system/docker.service.d/override.conf
[Unit]
After=network-online.target firewalld.service netfilter-persistent.service
Wants=network-online.target

sudo iptables -P FORWARD ACCEPT
sudo apt-get install iptables-persistent

docker compose exec redis redis-cli FLUSHDB


