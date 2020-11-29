import os
import sys
os.system("g++ -g -c CommLib/NetComm/src/*.cpp")
os.system("ar cqs libnetcomm.a ./*.o")
os.system("mv *.o CommLib/NetComm/src/")
os.system("mv *.a CommLib/NetComm/src/")
os.system("g++ -g -c CryptoLib/src/*.cpp")
os.system("ar cqs libcryptorlib.a ./*.o")
os.system("mv *.o CryptoLib/src/")
os.system("mv *.a CryptoLib/src/")
os.system("g++ -g -o Host ./generatedSrc/Host.cpp -I./ibe -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/  -lcryptorlib -L./CryptoLib/src/  -lpcap -lboost_serialization  -libe -lpbc -lgmp -lpthread") # -lssl -lcrypto
os.system("g++ -g -o Gateway ./generatedSrc/Gateway.cpp -I./ibe -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib -L./CryptoLib/src/  -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread") # -lssl -lcrypto
os.system("g++ -g -o Server ./generatedSrc/Server.cpp -I./ibe -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib -L./CryptoLib/src/  -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread") # -lssl -lcrypto
os.system("g++ -g -o test ./generatedSrc/test.cpp -I./ibe -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib  -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread") # -lssl -lcrypto
