# Cryptovium (aka CryptoVM)

Cryptovium is an experimental virtual execution environment for cryptographic primitives written in C.  It has its own byte-encoded instruction set and features eight individually addressable 256-bit registers that can act as a source or a destination for instruction operands.  Instructions can also access external immediate data (read-only) that has been attached to the "CryptoVM instance" via a function call, and can send output data to a global "output buffer".  It implements no branch conditions, only very simple compare and verify operations that return an appropriate error code on failure.  All operands are length-checked by the interpreter, as are all writes to the global output buffer.


The best way to understand Cryptovium is to study the unit tests.  There is a full FIDO U2F register/authenticate implementation (from the perspective of a USB token) that adequately covers most use cases.


Cryptovium is incomplete - currently only SHA2, CURVE25519, ECC SECP256R1, and key derivation functions are implemented.

####Again, this is just an experiment - use at your own risk.




## Acknowledgements

curve25519 library from [Open Whisper Systems](https://github.com/WhisperSystems)

micro-ecc library from [Ken MacKay](https://github.com/kmackay/micro-ecc)


# License

[GNU GPLv3](http://www.gnu.org/licenses/gpl-3.0.txt)
