## 📦 Inštalácia

Spusti nasledujúci príkaz v termináli (napr. v LXC konte alebo bare-metal):

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/spekulanter/mikrotik-manager/main/install_in_lxc.sh)"



debug log:

journalctl -u mbm.service -f



restart service:

systemctl restart mbm.service
