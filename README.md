"Blowfish All The Things" crypt
===============================

https://password-hashing.net/submissions/specs/battcrypt-v0.pdf

Package battcrypt implements Steven Thomas's "Blowfish All The Things"
cryptographic hash function.

There are three costs that can be modified:

- Time, with 0 being 2 iterations, 1 being 3, 2 being 4, 3 being 6, 4 being
  8, 5 being 12, and so on.
- Upgrade, with 0 being 1 iteration, 1 being 2, 2 being 3, 3 being 4, 4
  being 6, 5 being 8, 6 being 12, and so on.
- Memory, with each value above 0 taking twice as much memory as the
  previous.

If time and memory stay the same, upgrade can be increased without input
from the user.

For comparable complexity to bcrypt, set time to 1, upgrade to 0, and memory
to `bcrypt_cost` - 2.
