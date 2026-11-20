# Başlangıç rehberi: sıfırdan sıkılaştırılmış bir sunucuya

🇬🇧 [English](GUIDE.md)

Bu rehber yalnızca sunucunuza SSH ile bağlanabildiğinizi varsayar. Ansible bilmeniz gerekmez.
Her komutun tek satırlık bir açıklaması, ne görmeniz gerektiği ve bir şey ters giderse ne yapacağınız yazılı.

**Plan:** denetim → raporu oku → Lynis "öncesi" → her seferinde **tek** güvenli kategori uygula
(önce kuru çalıştırma) → Lynis "sonrası" → karşılaştır.

İçindekiler

1. [Başlamadan önce: iki güvenlik alışkanlığı](#1-başlamadan-önce-iki-güvenlik-alışkanlığı)
2. [Nasıl çalıştıracağınızı seçin](#2-nasıl-çalıştıracağınızı-seçin)
3. [Yol A – yerel mod (sunucunun üzerinde, en basit)](#3-yol-a--yerel-mod-sunucunun-üzerinde-en-basit)
4. [Yol B – Windows'tan WSL ile](#4-yol-b--windowstan-wsl-ile)
5. [Denetimi çalıştırın](#5-denetimi-çalıştırın)
6. [Raporu okuyun](#6-raporu-okuyun)
7. [Lynis "öncesi"](#7-lynis-öncesi)
8. [Her seferinde tek kategori uygulayın](#8-her-seferinde-tek-kategori-uygulayın)
9. [Lynis "sonrası" ve karşılaştırma](#9-lynis-sonrası-ve-karşılaştırma)
10. [Bir şey ters giderse](#10-bir-şey-ters-giderse)
11. [Sözlük](#11-sözlük)

---

## 1. Başlamadan önce: iki güvenlik alışkanlığı

1. **SSH ya da güvenlik duvarıyla ilgili bir şey uygularken ikinci bir SSH oturumunu açık tutun.**
   Zaten açık olan bir oturum, sshd reload'unda ve güvenlik duvarı değişikliğinde kapanmaz. Yeni ayarlar
   girişleri bozarsa, o oturumdan düzeltirsiniz.
2. **Sağlayıcınızın web konsolunu şimdi bulun, ihtiyaç duyduğunuzda değil.** Her VPS sağlayıcısının
   (Hetzner, DigitalOcean, Contabo, OVH, ...) web panelinde size *SSH olmadan* terminal veren bir
   "Console" / "VNC" / "Rescue" düğmesi vardır. Bir kez açın ve giriş yapabildiğinizi kontrol edin.
   Bunun için kullanıcınızın bir **parolası** olmalı (konsol SSH anahtarı kullanmaz).
   Bilmiyorsanız şimdi belirleyin:

   ```bash
   sudo passwd $USER        # kullanıcınıza parola koyar; sudo ve web konsolu için kullanılır
   ```

## 2. Nasıl çalıştıracağınızı seçin

Ansible, kontrolleri ve değişiklikleri çalıştıran araçtır. Windows'ta doğrudan **çalışmaz**.

| | Yol A: yerel mod | Yol B: Windows'ta WSL |
|---|---|---|
| Ansible nerede çalışır | sunucunun kendisinde | Windows içindeki Linux'ta |
| Kurulum zahmeti | tek bir `apt install` | WSL + Ansible kurulumu |
| Kimin için | tek sunucu, ilk kez | birden fazla sunucu, raporları dizüstünde tutmak |

Emin değilseniz: **Yol A**.

## 3. Yol A – yerel mod (sunucunun üzerinde, en basit)

```bash
ssh emre@sunucunuz                         # normal sudo kullanıcınızla girin (root DEĞİL)
```
Sunucunuzun komut satırını görmelisiniz, ör. `emre@mail:~$`.

```bash
sudo apt update                            # paket listesini yeniler
sudo apt install -y ansible git make       # Ansible'ı kurar (+ indirmek için git, kısayollar için make)
ansible --version                          # çalıştığını kontrol eder
```
Beklenen: `ansible [core 2.16.x]` ya da benzeri. `apt` "Could not get lock" derse arka planda başka bir
güncelleme çalışıyordur – birkaç dakika bekleyip tekrar deneyin.

```bash
cd ~
git clone https://github.com/rosko35/server-hardening.git    # bu projeyi indirir
cd server-hardening
```

Bundan sonra her komuta `LOCAL=1` eklenir. Bu, Makefile'a `inventory/localhost.yml` kullanmasını söyler
(Ansible üzerinde çalıştığı makineyi yönetir, `-c local`, SSH kullanılmaz).

**`-K` nedir?** Ansible'ın çoğu kontrol için root yetkisine ihtiyacı var ve bunu `sudo` ile alıyor.
`-K` (uzun hâli `--ask-become-pass`), Ansible'ın başta bir kez sudo parolanızı sormasını sağlar:

```text
BECOME password:
```

Kullanıcınızın parolasını yazın (yazarken ekranda bir şey görünmez – bu normal) ve Enter'a basın.
Makefile `-K`'yı kendisi ekler. sudo'nuz hiç parola sormuyorsa `K=0` ekleyin.

> `sudo make ...` ya da `sudo ansible-playbook ...` **çalıştırmayın**. Normal kullanıcınızla çalıştırın, sudo'yu `-K` halletsin.
> Aksi hâlde proje kim olduğunuzu ve nereden bağlandığınızı göremez, SSH/fail2ban adımlarını reddeder.

> `tmux` ya da `screen` kullanıyorsanız bağlantı IP'niz görünmeyebilir. fail2ban adımı bunu söyler ve
> `EXTRA='-e harden_operator_ip=IP.ADRESİNİZ'` ister. IP'nizi düz bir SSH oturumunda `echo $SSH_CLIENT` ile bulun (ilk alan).

[5. Denetimi çalıştırın](#5-denetimi-çalıştırın) bölümüyle devam edin.

## 4. Yol B – Windows'tan WSL ile

WSL ("Windows Subsystem for Linux"), Windows içinde gerçek bir Ubuntu çalıştırır.

1. **PowerShell'i Yönetici olarak** açın (Başlat → "PowerShell" yazın → sağ tık → Yönetici olarak çalıştır):

   ```powershell
   wsl --install -d Ubuntu-24.04       # WSL'i ve Ubuntu 24.04'ü kurar
   ```
   İstendiğinde bilgisayarı yeniden başlatın. Sonra bir Ubuntu penceresi açılır ve yeni bir UNIX kullanıcı adı
   ile parola ister – bu yalnızca WSL içindir, sunucunuzdakinden farklı olabilir.

2. Ubuntu (WSL) penceresinde:

   ```bash
   sudo apt update && sudo apt install -y ansible git make openssh-client   # araçlar
   cd ~                                                                       # Linux ev dizininiz
   git clone https://github.com/rosko35/server-hardening.git
   cd server-hardening
   ```
   **Linux ev dizininize (`~`) klonlayın, `/mnt/c/...` altına değil.** Windows klasörleri Linux açısından
   herkesin yazabildiği dizinlerdir ve Ansible bu durumda `ansible.cfg`'yi sessizce yok sayar.

3. SSH anahtarınız: anahtarınız Windows'taysa (`C:\Users\siz\.ssh\id_ed25519`), WSL'e kopyalayın:

   ```bash
   mkdir -p ~/.ssh && cp /mnt/c/Users/<siz>/.ssh/id_ed25519* ~/.ssh/   # anahtar çiftini kopyalar
   chmod 600 ~/.ssh/id_ed25519                                          # ssh başkalarının okuyabildiği anahtarı reddeder
   ssh -i ~/.ssh/id_ed25519 emre@sunucunuz true && echo OK              # test: OK yazmalı
   ```

4. Ansible'a sunucunuzu tanıtın:

   ```bash
   cp inventory/hosts.example.yml inventory/hosts.yml    # size özel kopya (git'e girmez)
   nano inventory/hosts.yml                              # düzenleyin: ansible_host, ansible_user, ansible_port
   ```
   `Ctrl+O`, Enter ile kaydedin, `Ctrl+X` ile çıkın.

5. Bağlantıyı test edin:

   ```bash
   ansible -i inventory/hosts.yml hardening_targets -m ping     # sunucuya "orada mısın?" diye sorar
   ```
   Beklenen: `mail | SUCCESS => { "ping": "pong" }`. `Host key verification failed` görürseniz sunucuya bir kez
   elle bağlanın (`ssh emre@sunucunuz`), `yes` deyin ve tekrar deneyin.

Yol B'de aşağıdaki tüm komutlarda `LOCAL=1` yazmayın; raporlar `reports/mail/` altına düşer (envanterinizdeki host adı).

## 5. Denetimi çalıştırın

```bash
make audit LOCAL=1          # Yol A
make audit                  # Yol B
```
Ne yapar: sunucuyu okur (dinleyen portlar, SSH ayarları, kullanıcılar, güncellemeler, güvenlik duvarı, ...) ve bir rapor yazar.
**Hiçbir şeyi değiştirmez.** İlk yazılan satır tam komuttur, ör.
`+ ansible-playbook -i inventory/localhost.yml --ask-become-pass site.yml --tags audit`.

Beklenen çıktı: bolca yeşil `ok:` satırı ve bazı `skipping:` satırları, sonra şuna benzer bir özet:

```text
TASK [Audit | Summary]
ok: [localhost] => msg:
  - Findings: 0 critical, 4 high, 5 medium, 6 low, 2 info
  - Report: .../reports/localhost/audit-report.md
...
PLAY RECAP
localhost : ok=60  changed=0  unreachable=0  failed=0  skipped=25
```

`changed=0`, sunucuda hiçbir şeyin değişmediğini doğrular. Kırmızı `fatal:` satırları görürseniz [10. bölüme](#10-bir-şey-ters-giderse) bakın.

## 6. Raporu okuyun

```bash
less reports/localhost/audit-report.md      # çıkmak için q; Yol B: reports/mail/audit-report.md
```

- **Summary**: önem derecesine göre sayılar.
- **Findings** tablosu: *ne* bulundu, *neden önemli*, *bu proje nasıl düzeltir*, hangi **anahtar** düzeltir,
  ve **değişiklik riski** (uygularken ne kadar dikkatli olmanız gerektiği).
- **Listening services**: her port, sahibi olan program, internetten erişilebilir olup olmadığı.
  Web + e-posta sunucusunda beklenenler: `22` (sshd), `80/443` (nginx), `25/465/587/993` (postfix/dovecot).
  Bunların dışında dışarıya açık bir şey varsa sorgulamaya değer.
- **Firewall plan**: dinleyen servislerden üretilmiş önerilen bir `firewall_allowed_ports` listesi.
- `audit-report.json` aynı verileri betikler için içerir.

İpucu: Yol B'de Markdown dosyasını daha güzel görmek için VS Code'da açın (`code reports/mail/audit-report.md`).

## 7. Lynis "öncesi"

Lynis, 0–100 arası bir "hardening index" veren bağımsız bir denetim aracıdır. Hiçbir şeyi değiştirmeden *önce* ölçün:

```bash
make lynis-before LOCAL=1        # eksikse lynis paketini kurar, sonra tarar (1–3 dakika)
```
Sonunda beklenen: `Lynis hardening index (before): NN / 100`.
Dosyalar: `reports/<host>/lynis-before.dat` (ham) ve `lynis-before.md` (okunabilir).
Sunucudaki tek değişiklik `lynis` paketinin kurulmasıdır (ve raporu `/var/log/server-hardening/` altında).
apt'nin paket listelerinde `lynis` henüz yoksa (örneğin listeleri silinmiş bir bulut imajında), kurulumdan önce
listeler `apt-get update` ile yenilenir; bu, yalnızca paket listelerini günceller, başka bir şey kurmaz. Aynısı ufw,
fail2ban ve unattended-upgrades kurulumu için de geçerlidir.

## 8. Her seferinde tek kategori uygulayın

**Her** kategori için düzen aynıdır:

```bash
make apply-<kategori> LOCAL=1 CHECK=1   # 1. kuru çalıştırma: neyin DEĞİŞECEĞİNİ gösterir (--check --diff), hiçbir şeyi değiştirmez
make apply-<kategori> LOCAL=1           # 2. gerçekten uygular
make audit LOCAL=1                      # 3. tekrar denetim: bulgu kaybolmuş olmalı
```

Kuru çalıştırmadaki diff'te `+` ile başlayan satırlar eklenecekleri, `-` ile başlayanlar kaldırılacakları gösterir.
Okuyun. Sizi şaşırtan bir şey varsa uygulamadan önce durun ve sorun.

Önerilen sıra (en düşük riskten başlayarak):

### 8.1 Otomatik güvenlik güncellemeleri – risk: düşük

```bash
make apply-auto-updates LOCAL=1 CHECK=1
make apply-auto-updates LOCAL=1
```
`unattended-upgrades` kurar, yalnızca güvenlik güncellemeleriyle sınırlar, **asla yeniden başlatmaz**.
Kontrol: `sudo unattended-upgrade --dry-run -d 2>&1 | tail` neyi kuracağını gösterir.

### 8.2 Dosya izinleri – risk: düşük

```bash
make apply-file-permissions LOCAL=1 CHECK=1
make apply-file-permissions LOCAL=1
```
Yalnızca izin bitlerini kaldırır (ör. `/etc/crontab` 644 → 600). Eski izinler geri alma için saklanır.

### 8.3 fail2ban – risk: düşük/orta

```bash
make apply-fail2ban LOCAL=1 CHECK=1
make apply-fail2ban LOCAL=1
```
10 dakika içinde 5 başarısız SSH girişinden sonra IP'yi 1 saat banlar. Mevcut IP'niz asla banlanmaz.
Kontrol: `sudo fail2ban-client status sshd`.

### 8.4 SSH – risk: YÜKSEK, önce bunu okuyun

Önce: sunucuya **ikinci bir SSH oturumu** açın ve ona dokunmayın.

```bash
make apply-ssh LOCAL=1 CHECK=1    # diff, yeni /etc/ssh/sshd_config.d/01-server-hardening.conf dosyasını gösterir
make apply-ssh LOCAL=1
```
Playbook `SSH changes are BLOCKED` yazarsa bilerek reddetmiştir – nedenini okuyun
(genellikle: kullanıcınız için SSH anahtarı bulunamadı, bu yüzden parola girişini kapatmaz).

Bittikten sonra **dizüstünüzden üçüncü, yeni bir SSH oturumu açın.** Ancak o çalışırsa fazladan oturumları kapatın.

### 8.5 Güvenlik duvarı – risk: YÜKSEK, önce bunu okuyun

1. Denetim raporundaki "Firewall plan" bölümüne ve önerilen listeye bakın.
2. Listeyi host değişkenlerinize koyun. Yol B: `inventory/hosts.yml` içinde host'unuzun altına.
   Yol A: `host_vars/localhost.yml` dosyasını oluşturun:

   ```yaml
   ---
   firewall_allowed_ports: ["22/tcp", "80/tcp", "443/tcp", "25/tcp", "465/tcp", "587/tcp", "993/tcp"]
   ```
   Web sitenizin ve e-postanızın ihtiyaç duyduğu her portu tutun. Yalnızca internetten erişilmemesi gerekenleri çıkarın.
3. İkinci SSH oturumu açıkken:

   ```bash
   make apply-firewall LOCAL=1 CHECK=1   # tam ufw komutlarını ve ENGELLENECEK portları yazdırır
   make apply-firewall LOCAL=1
   ```
   Dinleyen bir port listenizde yoksa rol **reddeder**, portu ve programı adıyla söyler.
   Ya onu `firewall_allowed_ports`'a ekleyin, ya da – gerçekten kapanmasını istiyorsanız – `firewall_acknowledge_closing`'e ekleyin.
4. Dışarıdan test edin: yeni bir SSH girişi, web sitenizi açın, bir e-posta gönderip alın.

### 8.6 Ağ sysctl ve hesaplar – risk: orta/düşük

```bash
make apply-sysctl LOCAL=1 CHECK=1     # önce diff'i okuyun
make apply-sysctl LOCAL=1
make apply-accounts LOCAL=1 CHECK=1   # önce diff'i okuyun
make apply-accounts LOCAL=1
```
`apply-accounts` yalnızca *yeni* hesapların varsayılanlarını değiştirir. Sistem hesaplarının kabuklarını kilitlemek
ikinci, ayrı bir anahtardır (`EXTRA='-e accounts_lock_system_shells=true'`) – rapordaki listeyi okuyana kadar ona dokunmayın.

## 9. Lynis "sonrası" ve karşılaştırma

```bash
make lynis-after LOCAL=1                 # aynı tarama tekrar
make compare HOST=localhost              # Yol B: make compare (HOST varsayılan olarak "mail")
```
Beklenen: şuna benzer bir tablo

```text
| Metric | Before | After | Change |
|---|---:|---:|---:|
| **Lynis hardening index** | NN | MM | **+X** |
```
`reports/<host>/lynis-comparison.md` aynı tabloyu ve hangi uyarı/önerilerin giderildiğini içerir.
README'deki "Sonuçlar" bölümüne yapıştırın.

## 10. Bir şey ters giderse

**Playbook kırmızı `fatal:` / `FAILED!` ile durdu.** `msg:` kısmını okuyun – güvenlik kontrolleri kendilerini açıklar
("Nothing was changed. ..."). Reddedilen bir adım hiçbir şeyi değiştirmemiştir. SSH'ta başarısız bir doğrulama eski
dosyayı otomatik geri yükler ve sshd reload edilmez.

**"BECOME password" yanlış / `Missing sudo password`.** Yanlış parola yazdınız ya da `K=0` kullandınız ama sudo parola istiyor.

**Tek bir kategoriyi geri alın:**

```bash
make rollback LOCAL=1                               # neyin geri yükleneceğini listeler (hiçbir şeyi değiştirmez)
make rollback LOCAL=1 CONFIRM=1 CATEGORIES=ssh      # yalnızca SSH'ı geri yükler
make rollback LOCAL=1 CONFIRM=1                     # her şeyi geri yükler
```

**Yeni SSH girişleri başarısız ama ikinci oturumunuz hâlâ açık.** O oturumda:

```bash
sudo rm /etc/ssh/sshd_config.d/01-server-hardening.conf   # sıkılaştırma drop-in'ini kaldırır
sudo sshd -t && sudo systemctl reload ssh                  # doğrular, sonra reload eder
sudo ufw disable                                           # sorun güvenlik duvarıysa
```

**Tamamen dışarıda kaldınız (açık oturum yok).** Sağlayıcının web konsolunu kullanın (1. bölüm):

1. Sağlayıcının kontrol paneline girin → sunucunuz → **Console** (bazen "VNC", "KVM", "Recovery console").
2. Kullanıcı adınız ve **parolanızla** girin (konsol, sunucuya takılı bir klavye gibidir; anahtarlar burada geçmez).
3. Yukarıdaki üç komutu çalıştırın (drop-in'i `rm`, `sshd -t && systemctl reload ssh`, `ufw disable`).
4. Dizüstünüzden tekrar SSH deneyin. Sonra `make rollback ... CONFIRM=1` çalıştırın ya da sorunu inceleyin.

Parolanız da yoksa: çoğu sağlayıcı bir **rescue system** sunar – panelden onunla açın, diskinizi bağlayın ve
`/etc/ssh/sshd_config.d/01-server-hardening.conf` dosyasını silin (ve `/etc/ufw/ufw.conf` içinde `ENABLED=no` yapın).

**Kendi IP'niz fail2ban tarafından banlandı** (ör. ev IP'niz değişti): konsoldan ya da başka bir IP'den
`sudo fail2ban-client set sshd unbanip IP.ADRESİNİZ`.

**Güvenlik duvarından sonra e-posta ya da web sitesi durdu:** `sudo ufw status numbered` kuralları gösterir; `sudo ufw allow 587/tcp`
tek bir portu hemen düzeltir; sonra bir sonraki çalıştırmada da kalması için onu `firewall_allowed_ports`'a ekleyin.

## 11. Sözlük

| Terim | Anlamı |
|---|---|
| Ansible | Sunuculara bir görev listesi ("playbook") uygulayan ve neyin değiştiğini raporlayan araç. |
| Playbook | Görevler içeren bir YAML dosyası, ör. `site.yml`. |
| Rol | Tek bir konu için yeniden kullanılabilir görev klasörü, ör. `roles/firewall/`. |
| Envanter (inventory) | Yönetilecek sunucuların listesi (`inventory/*.yml`). |
| `--check --diff` | Kuru çalıştırma: neyin değişeceğini göster, hiçbir şeyi değiştirme. |
| `-K` | sudo parolasını bir kez sor. |
| Idempotent | İki kez çalıştırınca ikincisinde hiçbir şey değişmez. |
| Drop-in | Ana dosyayı geçersiz kılan, `*.d/` klasöründeki küçük ek yapılandırma dosyası. |
| `sshd -t` | SSH sunucu yapılandırmasını uygulamadan hata için kontrol eder. |
| reload / restart | reload yapılandırmayı yeniden okur ve mevcut oturumları korur; restart önce her şeyi durdurur. |
| ufw | "Uncomplicated firewall", Ubuntu'daki standart güvenlik duvarı arayüzü. |
| Lynis | 0–100 arası hardening index veren bağımsız güvenlik denetim aracı. |
