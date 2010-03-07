PROJECT=snmp-server

UIP_CONF_IPV6=1
APPS=raven-webserver raven-lcd-interface snmpd

CONTIKI=/data/masters/dev/contiki-2.x

include $(CONTIKI)/Makefile.include

minimal-net:
	make TARGET=minimal-net $(PROJECT).minimal-net

raven: 	
	make TARGET=avr-raven $(PROJECT).elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(PROJECT).elf $(PROJECT).hex
	avr-size -C --mcu=atmega1284p $(PROJECT).elf
	rm -rf obj_native

cl:
	make TARGET=avr-raven clean
	make TARGET=minimal-net clean
	rm -rf obj_native
	rm symbols.c symbols.h $(PROJECT).elf $(PROJECT).hex
	rm -rf obj_avr-raven
	rm -rf obj_minimal-net
	rm $(PROJECT).avr-raven
	rm $(PROJECT).minimal-net
	
clmin:
	make TARGET=minimal-net clean
	rm -rf obj_native
	rm symbols.c symbols.h
	rm -rf obj_minimal-net
	rm $(PROJECT).minimal-net
	

clrav:
	make TARGET=avr-raven clean
	rm -rf obj_native
	rm symbols.c symbols.h $(PROJECT).elf $(PROJECT).hex
	rm -rf obj_avr-raven
	rm $(PROJECT).avr-raven

upload:
	avrdude -p m1284p -c jtag2 -P usb -v -F -e -U flash:w:"./$(PROJECT).hex"

run:
	sudo ./snmp-server.minimal-net
