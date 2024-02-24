# MPC-TSS (Multi-Party Computation based Threshold Signature Scheme) with Cypherock X1
This repository contains a working implementation of MPC processes designed to run inside of a [secure execution environment](https://github.com/Cypherock/x1_wallet_firmware/blob/main/docs/device_provision_auth.md) of Cypherock X1. Private and authenticated channels are set up between all devices in the group securely in the group setup phase. The architecture utilises hardware security and asset protection features offered by the Cypherock device and helps the group of users or an institution to own their assets completely. Further we have proposed an extension to the [BIP32 protocol](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) (`"Extended BIP32"`) with which any group member will be able to generate child or receive addresses from the group public key without having everyone else in the group to come online. All the polynomials required in the signature phase are generated randomly and consumed within the signature phase itself. 

The setting comprises of 3 sub-processes running independent MPC group sessions over the group of parties. These sub-process are:
1. User group setup <br/> A trustless setup to create a group
2. Distributed key generation <br/> Generates child public keys for the group
3. Transaction signing <br/> Sign ECDSA based transactions

# Watch demo
<a href="http://www.youtube.com/watch?feature=player_embedded&v=wue8B2U0vGA
" target="_blank"><img src="http://img.youtube.com/vi/wue8B2U0vGA/0.jpg" 
alt="DEMO" width="480" height="360" border="10" /></a>

# Usage
To execute and test the code, you'll require Cypherock X1 development devices to be able to flash the custom MPC firmware, present in the `vault` submodule. The firmware can be compiled using the build script provided in the `vault` submodule and can be flashed using `STM32_Programmer_CLI`. The CLI can be found in the `sdk` submodule. To be more specific, the project in `sdk/apps/node/` has to be executed. Before starting the program, make sure the flask communication server is running which can be found in the `server` directory. Watch the demo video to understand the usage of the CLI tool and its features.

# Future Work
We are currently researching various modern cryptography schemes to make the institutional digital asset management work in a true self-custody setup with the access control policy enforced through a decentralised network. We are researching the usage of schemes like homomorphic encryption using class groups (the `class-groups` submodule) which do not require any range proofs but other ZKPs to verify the correctness of the encryption operation. We are currently testing the generation of zk-SNARK proofs on the Cypherock X1 device using the Groth-16 implementation in the `zk-snark` submodule.
