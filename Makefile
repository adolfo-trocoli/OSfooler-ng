# Define target file name
TARGET = osfooler 

# Define source file name
SRC = osfooler.c

# Define object file name
OBJ = $(SRC:.c=.o)

SYSTEM=/etc/systemd/system

PYTHON = python3
VENV = bubble
OSNAME="Microsoft Windows 2000 SP4"
OSGENRE=Windows
P0F="2000 SP4"

# Default target
all: $(TARGET) $(VENV) service

# Compile the C file
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile the object file
%.o: %.c
	$(CC) $(CFLAGS) -DVENV="$(VENV)" -DDIR="$(ROOTDIR)" -c $< -o $@

clean:
	rm -rf $(OBJ) $(TARGET) $(VENV)

$(SYSTEM)/osfooler.service:
	cp service/osfooler.service /etc/systemd/system/

$(SYSTEM)/osfooler.service.d:
	mkdir $@
	
$(SYSTEM)/osfooler.service.d/osfooler.conf:  | $(SYSTEM)/osfooler.service.d
	@echo "Building $@"
	@echo OSNAME="${OSNAME}" > $@
	@echo OSGENRE="${OSGENRE}" >> $@
	@echo P0F="${P0F}" >> $@

service: $(SYSTEM)/osfooler.service $(SYSTEM)/osfooler.service.d $(SYSTEM)/osfooler.service.d/osfooler.conf
	chown root:root $^
	chmod 644 $^
	systemctl daemon-reload
	systemctl enable osfooler.service

$(VENV):
	$(PYTHON) -m venv $@
	. $@/bin/activate
	$(PYTHON) -m pip install -r requirements.txt

	chmod -R 500 . 
	chown -R root:root .

.PHONY: all clean service
