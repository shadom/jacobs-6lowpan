echo "Testing string:"
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] 1.3.6.1.2.1.1.11.0
snmpset -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] 1.3.6.1.2.1.1.11.0 s abc
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] 1.3.6.1.2.1.1.11.0
snmpset -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] 1.3.6.1.2.1.1.11.0 s abcdef
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] 1.3.6.1.2.1.1.11.0

echo "Testing integer"
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.1.0
snmpset -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.1.0  i 123
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.1.0

echo "Testing  uinteger"
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.2.0
snmpset -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.2.0  u 1234
snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232] .1.3.6.1.2.1.1234.2.0



