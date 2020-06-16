# whpexp
A collection of (not necessarily useful) Windows Hypervisor Platform experiments in Rust.

# payloadfuzz 

The [payloadfuzz](https://github.com/epakskape/whpexp/tree/master/payloadfuzz) project experiments with generating payloads in different ways and then executing them within a bare bones protected mode virtual machine.

## Installation

To run payloadfuzz, you need Rust nightly installed and need to install and start a local redis server. The redis server is used to store the collection of valid and invalid payloads for a given payloadfuzz session.

```
rustup default nightly
wsl sudo apt-get install redis-server
wsl redis-server
```

## Supported generators

The reverse nop generator attempts to generate an x64 nop sled in a manner similar to [Opty2](https://github.com/rapid7/metasploit-framework/blob/master/modules/nops/x86/opty2.rb) in the Metasploit framework. To ensure that the nop sled can be executed from each offset, the nop sled is generated in reverse starting with the last byte and ending with the first byte. Rather than attempting to this in a smart way, the reverse nop generator simply attempts to brute force the set of valid bytes that can precede other bytes. This is woefully inefficient, but it's a useful example.

