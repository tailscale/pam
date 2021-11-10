SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))

all: pam_test pam_ignore.so

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) -I$(SRC) -c $< -o $@

pam_test: pam_test.o
	$(CC) $< -o $@ -ldl -lpam

pam_ignore.so: pam_ignore.o
	$(CC) -fPIC -DPIC -shared -rdynamic $< -o $@
