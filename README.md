## Test Wireguard 
Python app change wireguard config 
Work on Linux

## Installation

```bash
sudo apt install wg-quick
```
Install and make AmneziaWG Linux

```bash
# Ubuntu/Debian
sudo apt install software-properties-common
sudo add-apt-repository ppa:amnezia/ppa
sudo apt update
sudo apt install amneziawg amneziawg-tools

# Or build from source
git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
cd amneziawg-linux-kernel-module/src
make
sudo make install

git clone https://github.com/amnezia-vpn/amneziawg-tools.git
cd amneziawg-tools/src
make
sudo make install
```

## Usage

```bash
sudo python3 main.py -c ./conf \
    --h1 12345 --h2 67890 --h3 11111 --h4 22222 \
    --jc-values 0,3,5,10,15 \
    --jmin-values 40,50,64 \
    --jmax-values 100,150,200,300 \
    --s1-values 0,50,100 \
    --s2-values 0,50,100 \
    --ping-count 10 \
    --ping-target 8.8.8.8
```
