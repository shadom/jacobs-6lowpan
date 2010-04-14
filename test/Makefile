SNMPGET = snmpget -v 1 -c public udp6:[aaaa::206:98ff:fe00:232]
SNMPGETNEXT =  snmpgetnext -v 1 -c public udp6:[aaaa::206:98ff:fe00:232]

INPUTS= $(wildcard *.in)

test:
	@for m in $(INPUTS); do					\
		echo -n "GET: trying $$m...";				\
        c=`cat $$m`; \
		$(SNMPGET) $$c 1>$$m.out 2>$$m.out;				\
		diff expect/$$m.out $$m.out > $$m.diff || 		\
			{ cat $$m.diff; exit 1; };			\
		rm -f $$m.diff;						\
		echo " ok";						\
	done

	@for m in $(INPUTS); do					\
		echo -n "GETNEXT: trying $$m...";				\
        c=`cat $$m`; \
		$(SNMPGETNEXT) $$c 1>$$m.out 2>$$m.out;				\
		diff expect/$$m.next.out $$m.out > $$m.diff || 		\
			{ cat $$m.diff; exit 1; };			\
		rm -f $$m.diff;						\
		echo " ok";						\
	done
    

clean:
	rm -rf *.out *.diff
