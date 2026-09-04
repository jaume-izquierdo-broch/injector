CC = gcc

CFLAGS = -Ilib -Wall -Wextra -municode

SRC = src/main.c src/wmi.c

OUT = build/main.exe

DLL_SRC = src/dll.c

DLL_OUT = build/dll.dll

all:
	if not exist build mkdir build
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) -lole32 -loleaut32 -lwbemuuid
	$(CC) -shared $(CFLAGS) $(DLL_SRC) -o $(DLL_OUT) -luser32

clean:
	if exist build rmdir /s /q build