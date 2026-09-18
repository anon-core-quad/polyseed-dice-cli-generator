This repository is a fork of the [polyseed-examples](https://github.com/tevador/polyseed-examples) 

Is meant as experiment to just create a command line tool to generate Polyseeds mnemonics starting from a dice throwns to add more entropy.
Is meanted to be used in cases when the hardware is minimal or you have just a pc meanted only offline wallet generations.

This is a **BETA**. Just an exercise for now.

Thanks to [tevador](https://github.com/tevador) for the project.

All of the code examples require the library to be built and installed on the local machine:

```
git clone https://github.com/tevador/polyseed.git
cd polyseed
mkdir build
cd build
cmake ..
make
sudo make install
```


Install dependencies:

# Debian based
```
sudo apt install libsodium-dev libutf8proc-dev openssl-dev
```

# Fedora based
```
sudo dnf install libsodium-dev libutf8proc-dev openssl-devel

```

Build and run:
```
make
./build/polyseed-dice-generator 
```

