CXX_X86 = i686-w64-mingw32-g++
CXX_X64 = x86_64-w64-mingw32-g++
CXXFLAGS = -O3 -Wall -Wextra -static

SRC_CPP = source/WinScalpel.cpp
SRC_C32 = source/hde32.c
SRC_C64 = source/hde64.c

TARGET_X86 = bin/WinScalpel_x86.exe
TARGET_X64 = bin/WinScalpel_x64.exe

all:
	mkdir -p bin
	@echo "[*] Compiling x86 (32-bit) version..."
	$(CXX_X86) $(CXXFLAGS) $(SRC_CPP) $(SRC_C32) -o $(TARGET_X86)
	@echo "[*] Compiling x64 (64-bit) version..."
	$(CXX_X64) $(CXXFLAGS) $(SRC_CPP) $(SRC_C64) -o $(TARGET_X64)
	@echo "[+] Build completed successfully!"

clean:
	rm -f $(TARGET_X86) $(TARGET_X64)