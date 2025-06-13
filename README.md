# Memento

Web aplikacija za dijeljenje slika.

**GitHub:** https://github.com/LorenzoA0/memento

**Opis**

Memento je Python/Flask aplikacija koja omogućava:
- **Registraciju i prijavu** korisnika uz sigurnu obradu lozinki (Werkzeug).
- **Upload i prikaz fotografija**, sačuvane kao binarni podaci u bazi (SQLAlchemy).

---

## Tehnologije

- **Jezik:** Python  
- **Web framework:** Flask  
- **Sigurnost i hash lozinki:** Werkzeug  
- **ORM:** SQLAlchemy  
- **Frontend:** HTML5, CSS3, Font Awesome  

---

## Arhitektura

Projekt koristi **MVC** (Model-View-Controller) pattern:
- **Modeli** — definicija baze podataka  
- **Kontroleri (rute)** — Flask route handleri za registraciju, login, upload, dashboard...  
- **Šabloni (views/templates)** — HTML + Jinja2 + CSS3 + Font Awesome

---

## Glavne funkcije

- Registracija i prijava korisnika  
- Sigurno hashiranje lozinki preko Werkzeug  
- Upload fotografija putem web-forme  
- Čuvanje slika u bazu kao BLOB (SQLAlchemy)  
- Prikaz uploadanih fotografija svih korisnika na dashboard-u

---

## Instalacija

1. Klonirajte repozitoriju i uđite u direktorijum:
   ```bash
   git clone https://github.com/LorenzoA0/memento.git
   cd memento
2. Instaliranje tehnologija koje projekat zahtijeva:
   ```bash
   pip install -r requirements.txt
3. Pokrenite XAMPP i aktivirajte Apache i MySQL module
4. U root projekta pokrenite flask aplikaciju:
   ```bash
   python app.py / flask run
