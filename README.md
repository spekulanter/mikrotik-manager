Install:

bash -c "$(wget -qLO - https://raw.githubusercontent.com/spekulanter/mikrotik-manager/main/install_in_lxc.sh)"



debug log:

journalctl -u mbm.service -f



restart service:

systemctl restart mbm.service
