## AccAu8 Usage
AccAu8 is a protocol for authentication.

## Prerequisite 
The code is currently compatible with the linux platform.

- System version

Expected Ubuntu 20.04

- g++

Minimal version 9.3.0

- python3

```sudo apt-get install python3.7```

- libpcap-dev

```sudo apt-get install libpcap-dev```

- boost

```sudo apt-get install libboost-dev libboost-all-dev```

- openssl

```sudo apt-get install openssl libssl-dev```


## Running



After installing the package go into folder  ```/generatedAccAu8``` and run

 ```python3 compile.py``` 

 (This step can be ignored if source code is not provided)

 This will result three binaries ```./Host, ./Server, ./Gateway```

### For single machine running

 execute in the following order:

 - ```sudo ./Server```


 - ```sudo ./Host``` + 回车 + ```127.0.0.10``` 


 - ```sudo ./Gateway```


 ### For multi tasking
Due to the inablity of configuring the network through files now, we can only support the network topo in the following:


Network components: 
- PC1: HOST1
- PC2: HOST2 + GATEWAY + SERVER

In PC2: 