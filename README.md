# KI-KDC-AES

|    NRP     |      Name      |
| :--------: | :------------: |
| 5025241145 | Lyonel Oliver Dwiputra |
| 5025241177 | Hosea Felix Sanjaya |

## File

| File | Isi |
|---|---|
| `aes.py` | AES-128 untuk satu blok 16 byte |
| `kdc.py` | Server KDC, membuat session key dan ticket |
| `alice.py` | Minta session key ke KDC, lalu connect ke Bob |
| `bob.py` | Menunggu Alice, memeriksa ticket, lalu chat |
| `network.py` | Kirim dan terima pesan lewat TCP (4 byte panjang, lalu isi pesan) |
| `utils.py` | Enkripsi banyak blok (ECB dan padding PKCS#7), nonce, input key, chat |
| `config.py` | IP, port, dan ID |
| `test.py` | Tes lokal: AES dengan vektor FIPS-197, enkripsi dan padding, langkah 3 sampai 5. Jalankan `python test.py` |

## Alur key distribution

```
1. Alice -> KDC   : ID_A, ID_B, N1                        
2. KDC   -> Alice : E(Ka, [Ks, N1, ticket])
                    ticket = E(Kb, [Ks, ID_A, ID_B])
3. Alice -> Bob   : ticket
4. Bob   -> Alice : E(Ks, N2)
5. Alice -> Bob   : E(Ks, f(N2))                          
```

Ks adalah 16 byte acak dari KDC. Setelah langkah 5, semua pesan chat dienkripsi dengan Ks.

KDC dan Bob jadi server, Alice jadi client. Koneksi Alice ke Bob dipakai dua arah, jadi keduanya bisa mengirim dan menerima.

## Cara menjalankan


Di laptop Alice, ganti IP di `config.py` dengan IP laptop KDC dan Bob, contoh:

```python
KDC_IP = "192.168.1.10"
BOB_IP = "192.168.1.20"
```

Lalu jalankan sesuai urutan:

```
python kdc.py      # laptop KDC
python bob.py      # laptop Bob
python alice.py    # laptop Alice
```

Key harus 16 karakter ASCII. Key Alice yang diisi di KDC harus sama dengan yang diketik di `alice.py`, begitu juga key Bob.

Untuk ganti key di KDC tanpa restart, ketik `/ganti` di terminal KDC lalu masukkan key Alice dan key Bob yang baru.

Port 5000 (KDC) dan 5002 (Bob) harus dibuka di firewall.

## Chat

- Ketik pesan lalu Enter. Plaintext harus ASCII.
- Pengirim melihat ciphertext dalam hex. Penerima melihat ciphertext dan plaintext.
- `/keluar` menutup sesi. Alice dan Bob lalu diminta key lagi, dan langkah 1 sampai 5 diulang dengan session key baru.
- Ctrl+C untuk keluar.

## Wireshark

Filter:

```
tcp.port == 5000 || tcp.port == 5002
```
