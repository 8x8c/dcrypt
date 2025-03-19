# Dcrypt 

Double encryption: first AES-256-GCM-SIV, then XChaCha20-Poly1305.  Incredibly easy to use. see /docs 

Meet-In-The-Middle attacks do not work as long as it is a different algo and key. If you were to encrypt twice with aes, for example, a meet-in-the-middle attack would be a concern. 
