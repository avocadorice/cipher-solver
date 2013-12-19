Usage: python unscramble.py <ciphertext-input-file> <dictionary-input-file>

Note: use the already provided "words-sorted-by-pattern" file, which is presorted by letter pattern and word frequencies.

Example:

user$ cat ciphertext-mod
MGG MGSDZ ULC RMUBLUSRCO AOKDBC HCAU ULC TKCR
RLKGC MGG ULC RSFMD BMFC MDV RCDU NMOCXSSU ICOTMDU USS
SYUIKVC KD ULC VKIUMDBC M RKGVBMU VKV ZOSRG

user$ python unscramble.py ciphertext-mod words-sorted-by-pattern
Score: 84
ALL ALONG THE WATCHTOWER PRINCE KEPT THE VIEW WHILE ALL THE WOMAN CAME AND WENT BAREFOOT SERVANT TOO OUTSIDE IN THE DISTANCE A WILDCAT DID GROWL TWO RIDER WERE APPROACHING THE WIND BEGIN TO HOWL
