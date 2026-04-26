# Legion — Bezpieczeństwo komunikacji

Ten dokument wyjaśnia w jaki sposób Legion chroni Twoje wiadomości, pliki i tożsamość.
Wszystkie opisane mechanizmy wynikają bezpośrednio z kodu źródłowego aplikacji.

---

## Czym jest Legion

Legion to komunikator zaprojektowany od podstaw z myślą o prywatności i bezpieczeństwie.
Nie korzysta z żadnych centralnych serwerów. Nie ma firmy która przechowuje Twoje dane.
Twój węzeł komunikuje się bezpośrednio z węzłem rozmówcy — przez sieć Tor.

---

## Sieć Tor — anonimowość na poziomie sieci

Każda wiadomość i każdy plik przechodzi przez **sieć Tor** — zdecentralizowaną sieć
węzłów pośredniczących, która ukrywa źródło i cel połączenia.

- Twój prawdziwy adres IP nigdy nie jest widoczny dla rozmówcy
- Adres rozmówcy nie jest widoczny dla Ciebie
- Pośrednicy w sieci Tor widzą tylko zaszyfrowany ruch — nie jego zawartość
- Każdy węzeł Legion działa jako ukryta usługa Tor (adres `.onion`)
- Połączenia są akceptowane wyłącznie z sieci Tor — zero możliwości niechronionego ruchu

---

## Szyfrowanie wiadomości

Każda wiadomość prywatna jest szyfrowana kluczem publicznym odbiorcy.

**Algorytm:** X25519 (wymiana kluczy) + XSalsa20-Poly1305 (szyfrowanie z uwierzytelnianiem)
— implementacja przez bibliotekę **libsodium** (PyNaCl), uznaną za bezpieczną przez
kryptografów na całym świecie.

Co to oznacza w praktyce:

- Tylko Ty i Twój rozmówca możecie odczytać treść wiadomości
- Nikt po drodze — ani operator relay, ani węzeł Tor — nie może jej odczytać
- Modyfikacja wiadomości w trakcie przesyłu jest wykrywana i wiadomość jest odrzucana
- Każda wiadomość ma unikalny losowy nonce — nawet te same słowa wyglądają
  zupełnie inaczej przy każdym szyfrowaniu

---

## Podpisy cyfrowe

Każda wiadomość jest podpisana kluczem prywatnym nadawcy.

**Algorytm:** Ed25519 — standardowy algorytm podpisów cyfrowych, używany m.in. przez SSH.

Zanim jakakolwiek wiadomość zostanie przetworzona przez węzeł odbiorcy:

1. Weryfikowana jest sygnatura Ed25519
2. Sprawdzane jest że `id == SHA256(payload)` — payload nie został podmieniony
3. Sprawdzany jest czas życia wiadomości (TTL) — stare wiadomości są odrzucane

Wiadomość z nieprawidłową sygnaturą jest odrzucana natychmiast i cicho,
bez żadnej odpowiedzi nadawcy.

---

## Ochrona klucza prywatnego

Twój klucz prywatny to Twoja tożsamość. Legion chroni go na dwa sposoby:

1. **Nigdy nie opuszcza urządzenia** — klucz prywatny nie jest wysyłany przez sieć,
   nie jest przechowywany na żadnym serwerze zewnętrznym

2. **Szyfrowanie hasłem na dysku** — klucz jest szyfrowany przy zapisie:
   - **Argon2id** (OWASP-zalecany algorytm hashowania haseł) wyprowadza klucz
     szyfrujący z Twojego hasła — odporny na ataki słownikowe i GPU
   - **XSalsa20-Poly1305** (SecretBox) szyfruje klucz prywatny
   - Każde hasło generuje unikalną losową sól — te same hasła dają różne klucze

Hasło jest wymagane przy **każdym uruchomieniu** aplikacji — celowo, jako
dodatkowa warstwa ochrony w przypadku kradzieży urządzenia.

---

## Bezpieczeństwo plików i obrazów

Każdy plik i obraz przechodzi przez **dwustronną sanityzację**:

### Po stronie nadawcy (przed wysłaniem)

Biblioteka **Pillow** (Python Imaging Library) re-enkoduje każdy obraz od zera.
Proces ten usuwa **wszystkie** ukryte dane:

- Dane GPS i lokalizacja (EXIF)
- Model aparatu, obiektyw, ustawienia
- Data i godzina wykonania zdjęcia
- Profile ICC (informacje o kalibracji kolorów)
- Metadane XMP (Adobe, etc.)
- Miniatury wbudowane w plik
- Komentarze i opisy

Re-enkodowanie to nie "wyczyszczenie pól" — to zbudowanie nowego pliku od zera,
co jest bezpieczniejsze niż selektywne usuwanie metadanych.

### Po stronie odbiorcy (po odebraniu)

Ten sam proces sanityzacji wykonywany jest **ponownie** po odszyfrowaniu pliku.
Nawet jeśli nadawca pominął sanityzację lub używał zmodyfikowanej wersji aplikacji —
Twój węzeł wyczyści plik przed zapisem.

### Weryfikacja formatu

Przed sanityzacją sprawdzane są bajty nagłówka pliku ("magic bytes") — plik
nie może podszywać się pod inny format niż deklaruje.

---

## Plaintext nigdy nie jest na dysku

Wiadomości są przechowywane w lokalnej bazie danych **wyłącznie w formie zaszyfrowanej**.
Odszyfrowanie następuje wyłącznie w momencie odczytu przez API — wynik nie jest nigdy
zapisywany na dysk.

Oznacza to że nawet pełny dostęp do pliku bazy danych `node.db` nie pozwala odczytać
treści wiadomości bez znajomości hasła (które jest potrzebne do odblokowania klucza prywatnego).

---

## Filtrowanie nadawców

Legion akceptuje wiadomości wyłącznie od **znanych kontaktów**.

- Wiadomości prywatne: nadawca musi być w Twojej liście kontaktów
- Posty grupowe: autor musi być członkiem danej grupy
- Zaproszenia do grup: wyłącznie od istniejących kontaktów

Wiadomości od nieznanych adresów są odrzucane natychmiast i cicho — bez żadnej
odpowiedzi, co utrudnia skanowanie i enumerację aktywnych węzłów.

---

## Weryfikacja kontaktów (karty kontaktowe)

Karta kontaktowa — plik JSON wymieniany przy dodawaniu kontaktu — zawiera
**podpis cyfrowy Ed25519**. Podpis obejmuje klucz publiczny, adres `.onion`
i sugerowaną nazwę.

Twój węzeł weryfikuje podpis przed dodaniem kontaktu — nie można podszyć się
pod inną osobę, nawet znając jej adres `.onion`.

---

## PANIC BUTTON — natychmiastowe usunięcie danych

W Ustawieniach dostępny jest przycisk **"⚠ PANIC — Delete everything"**.

Po podwójnym potwierdzeniu usuwa z bazy danych:

- Tożsamość i zaszyfrowany klucz prywatny
- Wszystkie kontakty
- Całą historię wiadomości i pliki
- Wszystkie grupy i posty
- Kolejkę dostarczania

Operacja jest **nieodwracalna** i wykonywana natychmiast. Klucz prywatny
w pamięci jest kasowany, aplikacja wraca do ekranu tworzenia tożsamości.

---

## Czego Legion NIE gwarantuje

Uczciwe wyjaśnienie granic ochrony:

- **Bezpieczeństwo urządzenia** — jeśli Twój komputer jest zainfekowany malware'm
  lub ktoś ma do niego fizyczny dostęp gdy aplikacja działa (klucz w pamięci),
  ochrona kryptograficzna nie pomaga

- **Anonimowość metadanych** — Tor ukrywa IP, ale sam fakt komunikacji z danym
  `.onion` adresem jest trudny do ukrycia na poziomie analizy ruchu sieciowego
  przez zaawansowanego przeciwnika kontrolującego duże fragmenty sieci Tor

- **Bezpieczeństwo rozmówcy** — Legion nie może zagwarantować że urządzenie
  Twojego rozmówcy jest bezpieczne

- **Odporność na przymus** — żadna technologia nie chroni przed zmuszeniem
  do ujawnienia hasła

---

## Biblioteki kryptograficzne

Legion używa wyłącznie sprawdzonych, audytowanych bibliotek:

| Biblioteka | Zastosowanie |
|---|---|
| **libsodium** (via PyNaCl) | X25519, Ed25519, XSalsa20-Poly1305, Argon2id |
| **Pillow** | Sanityzacja obrazów, usuwanie metadanych |
| **Stem** | Zarządzanie Torem |

Żaden własny algorytm kryptograficzny nie został zaimplementowany w aplikacji.

---

## Kod źródłowy

Legion jest oprogramowaniem **open source** na licencji AGPL-3.0.
Każdy może przejrzeć kod, zweryfikować opisane mechanizmy i zgłosić błędy.

Bezpieczeństwo przez transparentność, nie przez ukrywanie.
