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
KDC_IP = "172.20.0.10"
BOB_IP = "172.20.0.20"
```

Lalu jalankan sesuai urutan:

```
python kdc.py      # laptop KDC
python bob.py      # laptop Bob
python alice.py    # laptop Alice
```

Key harus 16 karakter ASCII. Key Alice yang diisi di KDC harus sama dengan yang diketik di `alice.py`, begitu juga key Bob.

Port 5000 (KDC) dan 5002 (Bob) harus dibuka di firewall.

### Docker

Buat network sekali:

```
docker network create --subnet 172.20.0.0/24 kdcnet
```

Isi `config.py`:

```python
KDC_IP = "172.20.0.10"
BOB_IP = "172.20.0.20"
```

Jalankan di tiga terminal sesuai urutan:

```
docker run -it --rm --name kdc --network kdcnet --ip 172.20.0.10 -v "$PWD":/app -w /app python:3-slim python kdc.py
docker run -it --rm --name bob --network kdcnet --ip 172.20.0.20 -v "$PWD":/app -w /app python:3-slim python bob.py
docker run -it --rm --name alice --network kdcnet --ip 172.20.0.30 -v "$PWD":/app -w /app python:3-slim python alice.py
```

## Chat

- Ketik pesan lalu Enter. Plaintext harus ASCII.
- Pengirim melihat ciphertext dalam hex. Penerima melihat ciphertext dan plaintext.
- Ctrl+C untuk keluar.

## Ganti key tanpa restart

| Perintah | Di mana | Fungsi |
|---|---|---|
| `/ganti` | KDC | Ganti Ka dan Kb yang disimpan KDC |
| `/baru` | Alice / Bob | Tutup sesi, masukkan key lagi, lalu langkah 1 sampai 5 diulang dengan session key baru |

Untuk ganti key, `/ganti` dulu di KDC, lalu `/baru` di Alice dan Bob dan masukkan key baru yang sama. Masukkan key Bob dulu, baru Alice. Kalau key hanya diganti di satu sisi, decrypt akan gagal.

## Wireshark

Filter:

```
tcp.port == 5000 || tcp.port == 5002
```
