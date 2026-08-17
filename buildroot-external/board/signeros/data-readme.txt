SignerOS - data partition
=========================

This is partition 2 of a SignerOS stick. It is the only writable filesystem the
appliance can reach. Two kinds of file live here: PSBTs on their way to and from
the signer, and the watch-only export of a wallet the signer created.

Signing a transaction
---------------------

1. On your online machine, have your wallet build an unsigned transaction and
   export it as a PSBT. Copy that file into the root of this partition. Any
   name works as long as it ends in .psbt

2. Move the stick to the air-gapped machine and boot from it. SignerOS lists
   every *.psbt file it finds here, shows you the amounts, the destination
   addresses and the fee, and signs the one you choose after you enter your key.

3. The result is written back here as signed_<timestamp>.psbt - the input file
   is never modified. Use the shutdown button and wait for the machine to
   switch off before pulling the stick out: shutdown is what flushes this
   partition and scrubs the key material out of RAM.

4. Back on the online machine, hand signed_<timestamp>.psbt to your wallet to
   finalise and broadcast.

Creating a wallet
-----------------

Choosing "Create a wallet" generates a seed on the air-gapped machine and shows
you the recovery words once. They are NOT written here, or anywhere else, ever -
you write them on paper and type every one of them back to prove the copy is
correct. When the screen closes they are gone from the machine's memory and your
paper is the only copy in existence.

The one file that lands here is

    signeros-<fingerprint>-<timestamp>.descriptors.txt

It holds output descriptors and extended PUBLIC keys for four address types
(BIP84 native segwit, BIP86 taproot, BIP49 nested segwit, BIP44 legacy),
account 0. Import it on your online machine to watch the wallet and build
transactions for it:

    Sparrow        File -> Import Wallet -> Output Descriptor -> choose the file
    Bitcoin Core   importdescriptors, with "active": true

It contains no private key and cannot spend anything. It is not a backup: if you
lose the paper, this file will show you your coins and let you build
transactions you can never sign.

It is, however, worth keeping private. Anyone who reads it learns every address
that wallet will ever use, and its whole balance and history.

Check the first address printed in the file against what your wallet shows after
the import. If they match, the right file reached the right wallet.

What SignerOS does and does not touch here
------------------------------------------

  * It reads only files ending in .psbt, and only from this directory - it
    never descends into subdirectories.
  * It writes only signed_<timestamp>.psbt (and signed_<timestamp>.tx if the
    image was built with WRITE_FINAL_TX=1), plus a
    signeros-*.descriptors.txt when you create a wallet.
  * This partition is mounted noexec,nodev,nosuid. Nothing placed here can be
    executed by the appliance, whatever it claims to be.
  * Partition 1 is the boot partition. Nothing on the running system writes to
    it. Leave it alone.

Do not keep secrets on this partition
-------------------------------------

A PSBT contains no private keys, and neither does the descriptor export, which
is why both are safe to carry on a stick that touches an online machine. Your
mnemonic is typed - or generated and shown - on the air-gapped machine and is
never written anywhere by it. Do not put a seed phrase, a wallet backup or a key
file here yourself: this partition travels to a computer you have assumed is
compromised.
