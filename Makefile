CXX = g++
CXXFLAGS = -std=c++11 -I/usr/local/opt/sqlite/include -I/usr/local/Cellar/libbitcoin-system/3.8.0/include/Trust/wallet-core-3.1.0/include -I/usr/local/Cellar/libbitcoin-system/3.8.0/include/Trust/OpenCL-CLHPP/include
LDFLAGS = -L/usr/local/opt/sqlite/lib -L/usr/local/Cellar/libbitcoin-system/3.8.0/include/Trust/wallet-core-3.1.0/trezor-crypto/trezor-crypto -lsqlite3 -lTrezorCrypto -lssl -lcrypto -framework OpenCL
SOURCES = main4.cpp
EXECUTABLE = main4

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE)
