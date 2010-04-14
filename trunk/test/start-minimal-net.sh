sudo route add -6 aaaa::/64 tap0
sudo ip -6 address add aaaa::1/64 dev tap0
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo cp /etc/radvd.conf-mininet /etc/radvd.conf
sudo /etc/init.d/radvd stop
sudo /etc/init.d/radvd start
#nc6 -u aaaa::206:98ff:fe00:232 161

