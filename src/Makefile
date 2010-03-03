PROJECT=snmpd

include Makefile.${PROJECT}

all: $(PROJECT)
	make TARGET=avr-raven $(PROJECT).elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(PROJECT).elf $(PROJECT).hex
	avr-size -C --mcu=atmega1284p $(PROJECT).elf
	rm -rf obj_native

cl:
	make TARGET=avr-raven clean
	rm symbols.c symbols.h $(PROJECT).elf $(PROJECT).hex
	rm -rf obj_avr-raven
	rm $(PROJECT).avr-raven
	rm -rf obj_native	

upload:
	avrdude -p m1284p -c jtag2 -P usb -v -F -e -U flash:w:"./$(PROJECT).hex"

