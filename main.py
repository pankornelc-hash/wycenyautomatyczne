import os
import secrets
import string
import asyncio
from datetime import datetime, timedelta, date
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
from jose import JWTError, jwt

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Date
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, ConfigDict

# ==========================================
# 1. KONFIGURACJA I BEZPIECZEŃSTWO
# ==========================================
SECRET_KEY = "super-secret-key-faktury-zyski"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 dni

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./faktury_database.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. MODELE BAZY DANYCH
# ==========================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin") 

class AppSettings(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True, index=True)
    vat_rate = Column(Float, default=23.0)           # Domyślny VAT np. 23%
    income_tax_rate = Column(Float, default=19.0)    # Domyślny Podatek Dochodowy np. 19% lub 12%

class Invoice(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True, index=True)
    invoice_number = Column(String, unique=True, index=True, nullable=False)
    issue_date = Column(Date, nullable=False)
    client_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    
    # Dane finansowe podane przez użytkownika
    revenue_net = Column(Float, nullable=False) # Przychód Netto (Z faktury sprzedaży)
    cost_net = Column(Float, nullable=False)    # Koszty Netto poniesione
    cost_gross = Column(Float, nullable=False)  # Koszty Brutto poniesione
    
    # Stawki podatkowe pobrane w momencie zapisu (Snapshot)
    applied_vat_rate = Column(Float, nullable=False)
    applied_tax_rate = Column(Float, nullable=False)
    
    # Wyliczenia zachowane w bazie
    calc_income = Column(Float, nullable=False)       # Dochód (Przychód netto - Koszt netto)
    calc_income_tax = Column(Float, nullable=False)   # Kwota podatku dochodowego
    calc_vat_to_pay = Column(Float, nullable=False)   # VAT do zapłaty do US
    calc_net_profit = Column(Float, nullable=False)   # ZYSK NA CZYSTO (Na rękę)
    
    created_at = Column(Date, default=date.today)

# ==========================================
# 3. SCHEMATY PYDANTIC
# ==========================================
class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    model_config = ConfigDict(from_attributes=True)

class SettingsBase(BaseModel):
    vat_rate: float
    income_tax_rate: float

class InvoiceCreate(BaseModel):
    invoice_number: str
    issue_date: date
    client_name: str
    description: Optional[str] = None
    revenue_net: float
    cost_net: float
    cost_gross: float

class InvoiceResponse(InvoiceCreate):
    id: int
    applied_vat_rate: float
    applied_tax_rate: float
    calc_income: float
    calc_income_tax: float
    calc_vat_to_pay: float
    calc_net_profit: float
    model_config = ConfigDict(from_attributes=True)

# ==========================================
# 4. LOGIKA BIZNESOWA I AUTORYZACJA
# ==========================================
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401)
    return user

def initialize_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Konto admina
    admin_email = "admin@firma.pl"
    admin = db.query(User).filter(User.email == admin_email).first()
    if not admin:
        hashed = get_password_hash("Admin123!")
        new_admin = User(email=admin_email, hashed_password=hashed, role="admin")
        db.add(new_admin)
    # Ustawienia domyślne
    settings = db.query(AppSettings).first()
    if not settings:
        db.add(AppSettings(vat_rate=23.0, income_tax_rate=19.0))
    db.commit()
    db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(title="Kalkulator Zysków API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ==========================================
# 5. ENDPOINTY API
# ==========================================
@app.post("/api/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Nieprawidłowy e-mail lub hasło")
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

# --- USTAWIENIA (ADMIN) ---
@app.get("/api/settings", response_model=SettingsBase)
def get_settings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = db.query(AppSettings).first()
    return settings

@app.put("/api/settings")
def update_settings(payload: SettingsBase, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = db.query(AppSettings).first()
    settings.vat_rate = payload.vat_rate
    settings.income_tax_rate = payload.income_tax_rate
    db.commit()
    return {"msg": "Ustawienia zapisane"}

# --- FAKTURY ---
@app.get("/api/invoices", response_model=List[InvoiceResponse])
def get_invoices(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Invoice).order_by(Invoice.issue_date.desc(), Invoice.id.desc()).all()

@app.post("/api/invoices", response_model=InvoiceResponse)
def create_invoice(invoice: InvoiceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Pobierz aktualne stawki podatkowe
    settings = db.query(AppSettings).first()
    vat_r = settings.vat_rate
    tax_r = settings.income_tax_rate
    
    # --- MATEMATYKA ---
    # 1. Dochód
    income = invoice.revenue_net - invoice.cost_net
    
    # 2. Podatek dochodowy (tylko gdy jest dochód)
    income_tax = (income * (tax_r / 100)) if income > 0 else 0.0
    
    # 3. Zysk na czysto
    net_profit = income - income_tax
    
    # 4. Obliczenia VAT
    vat_należny = invoice.revenue_net * (vat_r / 100) # VAT, który my doliczyliśmy klientowi
    vat_naliczony = invoice.cost_gross - invoice.cost_net # VAT, który my zapłaciliśmy w kosztach
    vat_to_pay = vat_należny - vat_naliczony # Ile musimy oddać do Urzędu Skarbowego
    
    new_inv = Invoice(
        **invoice.model_dump(),
        applied_vat_rate=vat_r,
        applied_tax_rate=tax_r,
        calc_income=round(income, 2),
        calc_income_tax=round(income_tax, 2),
        calc_vat_to_pay=round(vat_to_pay, 2),
        calc_net_profit=round(net_profit, 2)
    )
    
    db.add(new_inv)
    db.commit()
    db.refresh(new_inv)
    return new_inv

@app.delete("/api/invoices/{inv_id}")
def delete_invoice(inv_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    inv = db.query(Invoice).filter(Invoice.id == inv_id).first()
    if inv:
        db.delete(inv)
        db.commit()
    return {"msg": "Usunięto"}

# ==========================================
# 6. FRONTEND (VUE 3 + TAILWIND) 
# ==========================================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    return """
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Zyski & Koszty</title>
        <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            body { 
                font-family: 'Plus Jakarta Sans', sans-serif; 
                background-color: #f8fafc; 
                color: #0f172a; 
            }
            .glass-panel {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 1rem;
                box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
            }
            .input-modern {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                color: #0f172a;
                border-radius: 0.5rem;
                padding: 0.6rem 1rem;
                font-size: 0.875rem;
                font-weight: 600;
                transition: all 0.2s ease;
                width: 100%;
            }
            .input-modern:focus {
                outline: none;
                border-color: #0ea5e9; 
                box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15);
                background: #ffffff;
            }
            .btn-primary {
                background: #0ea5e9;
                color: #ffffff;
                font-weight: 600;
                padding: 0.75rem 1.5rem;
                border-radius: 0.5rem;
                transition: all 0.2s ease;
                border: none;
                display: flex; align-items: center; justify-content: center; gap: 0.5rem;
            }
            .btn-primary:hover { background: #0284c7; }
            .btn-primary:active { transform: scale(0.98); }
            
            .nav-item {
                display: flex; align-items: center; gap: 0.75rem;
                padding: 0.75rem 1rem;
                border-radius: 0.5rem;
                font-size: 0.875rem;
                font-weight: 600;
                color: #64748b;
                transition: all 0.2s ease;
            }
            .nav-item:hover { color: #0f172a; background: #f1f5f9; }
            .nav-item.active { color: #0ea5e9; background: #e0f2fe; }

            .fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease; }
            .fade-enter-from, .fade-leave-to { opacity: 0; }
            .no-scrollbar::-webkit-scrollbar { display: none; }
        </style>
    </head>
    <body class="flex flex-col md:flex-row h-screen overflow-hidden">
        <div id="app" class="h-full flex w-full relative">
            
            <!-- TOAST -->
            <transition name="fade">
                <div v-if="toast.show" class="fixed top-6 right-6 z-[100] px-5 py-3 glass-panel shadow-lg flex items-center gap-3 font-semibold text-sm border-l-4"
                     :class="toast.type === 'error' ? 'border-red-500 text-red-700' : 'border-sky-500 text-sky-700'">
                    <i class="fa-solid" :class="toast.type === 'error' ? 'fa-circle-xmark text-red-500' : 'fa-check text-sky-500'"></i>
                    {{ toast.message }}
                </div>
            </transition>

            <!-- Ekran logowania -->
            <div v-if="!token" class="flex-1 flex flex-col items-center justify-center p-4">
                <div class="w-full max-w-sm">
                    <div class="mb-8 text-center">
                        <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-sky-100 text-sky-600 mb-4">
                            <i class="fa-solid fa-chart-pie text-2xl"></i>
                        </div>
                        <h2 class="text-2xl font-black text-slate-900 tracking-tight">Kalkulator Zysków</h2>
                        <p class="text-sm text-slate-500 mt-1 font-medium">Zaloguj się do systemu</p>
                    </div>
                    <div class="glass-panel p-6 sm:p-8 shadow-sm">
                        <form @submit.prevent="login" class="space-y-4">
                            <div>
                                <label class="block text-xs font-bold text-slate-600 mb-1">Adres E-mail</label>
                                <input type="email" v-model="loginData.username" required class="input-modern" placeholder="admin@firma.pl">
                            </div>
                            <div>
                                <label class="block text-xs font-bold text-slate-600 mb-1">Hasło</label>
                                <input type="password" v-model="loginData.password" required class="input-modern" placeholder="Admin123!">
                            </div>
                            <button type="submit" class="btn-primary w-full mt-2 py-3">Zaloguj się</button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Główna Aplikacja -->
            <template v-else>
                
                <!-- Sidebar (Desktop) -->
                <div class="hidden md:flex flex-col w-64 bg-white border-r border-slate-200 z-20 h-full flex-shrink-0">
                    <div class="p-6 border-b border-slate-100">
                        <h1 class="text-lg font-black text-slate-900 tracking-tight flex items-center gap-2">
                            <i class="fa-solid fa-chart-pie text-sky-500"></i> ZYSKI <span class="text-slate-400 font-medium">APP</span>
                        </h1>
                    </div>
                    <nav class="flex-1 px-4 py-6 space-y-1 overflow-y-auto no-scrollbar">
                        <button @click="setTab('dashboard')" class="nav-item w-full" :class="currentTab === 'dashboard' ? 'active' : ''">
                            <i class="fa-solid fa-file-invoice-dollar w-5 text-center"></i> Baza Faktur
                        </button>
                        <button @click="setTab('add_invoice')" class="nav-item w-full" :class="currentTab === 'add_invoice' ? 'active' : ''">
                            <i class="fa-solid fa-calculator w-5 text-center"></i> Kalkulator / Dodaj
                        </button>
                        <button @click="setTab('admin')" class="nav-item w-full" :class="currentTab === 'admin' ? 'active' : ''">
                            <i class="fa-solid fa-sliders w-5 text-center"></i> Administracja
                        </button>
                    </nav>
                    <div class="p-4 border-t border-slate-100 bg-slate-50">
                        <p class="text-sm font-bold text-slate-800 truncate px-2 mb-3">{{ user.email }}</p>
                        <button @click="logout" class="w-full text-sm font-semibold text-slate-500 hover:text-rose-600 bg-white border border-slate-200 py-2 rounded-lg transition">Wyloguj</button>
                    </div>
                </div>

                <!-- Mobile Header -->
                <div class="md:hidden fixed top-0 w-full bg-white z-50 flex justify-between items-center p-4 border-b border-slate-200 shadow-sm">
                    <span class="font-black text-lg text-slate-900 tracking-tight"><i class="fa-solid fa-chart-pie text-sky-500 mr-2"></i> ZYSKI</span>
                    <button @click="mobileMenuOpen = !mobileMenuOpen" class="text-slate-600 p-1"><i class="fa-solid fa-bars text-xl"></i></button>
                </div>
                
                <!-- Mobile Dropdown -->
                <transition name="fade">
                    <div v-if="mobileMenuOpen" class="md:hidden fixed top-[61px] left-0 w-full bg-white z-40 p-4 space-y-2 border-b border-slate-200 shadow-lg">
                        <button @click="setTab('dashboard')" class="nav-item w-full" :class="currentTab === 'dashboard' ? 'active' : ''"><i class="fa-solid fa-file-invoice-dollar w-5"></i> Baza Faktur</button>
                        <button @click="setTab('add_invoice')" class="nav-item w-full" :class="currentTab === 'add_invoice' ? 'active' : ''"><i class="fa-solid fa-calculator w-5"></i> Kalkulator / Dodaj</button>
                        <button @click="setTab('admin')" class="nav-item w-full" :class="currentTab === 'admin' ? 'active' : ''"><i class="fa-solid fa-sliders w-5"></i> Administracja</button>
                        <button @click="logout" class="nav-item w-full text-red-600 hover:bg-red-50 mt-4"><i class="fa-solid fa-arrow-right-from-bracket w-5"></i> Wyloguj</button>
                    </div>
                </transition>

                <!-- MAIN CONTENT AREA -->
                <main class="flex-1 overflow-y-auto w-full pt-20 md:pt-0 p-4 md:p-8 z-10 bg-slate-50">
                    <transition name="fade" mode="out-in">
                        
                        <!-- TAB: BAZA FAKTUR -->
                        <div v-if="currentTab === 'dashboard'" class="max-w-7xl mx-auto space-y-6">
                            
                            <div class="flex justify-between items-end border-b border-slate-200 pb-4">
                                <div>
                                    <h1 class="text-2xl font-black text-slate-900">Rejestr Faktur i Zysków</h1>
                                    <p class="text-sm text-slate-500 mt-1">Podgląd wszystkich przeprowadzonych kalkulacji.</p>
                                </div>
                            </div>
                            
                            <!-- Podsumowanie finansowe (Statystyki) -->
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                <div class="glass-panel p-5 bg-white border-l-4 border-sky-500">
                                    <p class="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Całkowity Przychód Netto</p>
                                    <p class="text-2xl font-black text-slate-900">{{ formatCurrency(totalRevenueNet) }}</p>
                                </div>
                                <div class="glass-panel p-5 bg-white border-l-4 border-rose-500">
                                    <p class="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Całkowite Koszty Netto</p>
                                    <p class="text-2xl font-black text-slate-900">{{ formatCurrency(totalCostNet) }}</p>
                                </div>
                                <div class="glass-panel p-5 bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-lg">
                                    <p class="text-xs font-bold text-emerald-100 uppercase tracking-widest mb-1">ZYSK NA CZYSTO (RAZEM)</p>
                                    <p class="text-3xl font-black">{{ formatCurrency(totalNetProfit) }}</p>
                                </div>
                            </div>

                            <!-- Tabela -->
                            <div class="glass-panel overflow-x-auto bg-white">
                                <table class="min-w-full text-left border-collapse">
                                    <thead class="bg-slate-50 border-b border-slate-200">
                                        <tr>
                                            <th class="px-5 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Faktura & Klient</th>
                                            <th class="px-5 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider">Data Wystawienia</th>
                                            <th class="px-5 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-right">Przychód Netto</th>
                                            <th class="px-5 py-4 text-xs font-bold text-slate-500 uppercase tracking-wider text-right">Koszty Netto</th>
                                            <th class="px-5 py-4 text-xs font-bold text-sky-600 uppercase tracking-wider text-right">Zysk Na Czysto</th>
                                            <th class="px-5 py-4 text-center"><i class="fa-solid fa-gear text-slate-400"></i></th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-slate-100">
                                        <tr v-for="inv in invoices" :key="inv.id" class="hover:bg-slate-50 transition">
                                            <td class="px-5 py-4">
                                                <div class="font-bold text-slate-900">{{ inv.invoice_number }}</div>
                                                <div class="text-xs font-semibold text-slate-500 mt-0.5">{{ inv.client_name }}</div>
                                            </td>
                                            <td class="px-5 py-4 text-sm font-medium text-slate-700">{{ inv.issue_date }}</td>
                                            <td class="px-5 py-4 text-sm font-bold text-slate-800 text-right">{{ formatCurrency(inv.revenue_net) }}</td>
                                            <td class="px-5 py-4 text-sm font-bold text-rose-600 text-right">{{ formatCurrency(inv.cost_net) }}</td>
                                            <td class="px-5 py-4 text-base font-black text-emerald-600 text-right bg-emerald-50/30">{{ formatCurrency(inv.calc_net_profit) }}</td>
                                            <td class="px-5 py-4 text-center">
                                                <button @click="deleteInvoice(inv.id)" class="text-slate-300 hover:text-red-500 p-2 transition"><i class="fa-solid fa-trash-can"></i></button>
                                            </td>
                                        </tr>
                                        <tr v-if="invoices.length === 0">
                                            <td colspan="6" class="px-6 py-12 text-center text-slate-400 font-medium">Brak dodanych faktur. Przejdź do zakładki Kalkulator, aby dodać pierwszą.</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- TAB: DODAWANIE (KALKULATOR NA ŻYWO) -->
                        <div v-else-if="currentTab === 'add_invoice'" class="max-w-6xl mx-auto space-y-6">
                            
                            <div class="border-b border-slate-200 pb-4">
                                <h1 class="text-2xl font-bold text-slate-900">Kalkulator & Nowa Faktura</h1>
                                <p class="text-sm text-slate-500 mt-1">Wprowadź dane, a system na żywo wyliczy obciążenia podatkowe i realny zysk.</p>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
                                <!-- Formularz Wprowadzania -->
                                <div class="lg:col-span-7 space-y-6">
                                    <form @submit.prevent="saveInvoice" class="glass-panel p-6 md:p-8 space-y-6 bg-white">
                                        
                                        <div>
                                            <h3 class="text-sm font-bold text-slate-900 border-b border-slate-100 pb-2 mb-4"><i class="fa-solid fa-file-lines text-slate-400 mr-2"></i> Dane z Faktury</h3>
                                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                                <div><label class="block text-xs font-semibold text-slate-600 mb-1">Numer Faktury</label><input type="text" v-model="form.invoice_number" required class="input-modern bg-slate-50 border-slate-200"></div>
                                                <div><label class="block text-xs font-semibold text-slate-600 mb-1">Data Wystawienia</label><input type="date" v-model="form.issue_date" required class="input-modern bg-slate-50 border-slate-200"></div>
                                                <div class="sm:col-span-2"><label class="block text-xs font-semibold text-slate-600 mb-1">Nazwa Klienta</label><input type="text" v-model="form.client_name" required class="input-modern bg-slate-50 border-slate-200"></div>
                                                <div class="sm:col-span-2"><label class="block text-xs font-semibold text-slate-600 mb-1">Opis / Tytuł (opcjonalnie)</label><input type="text" v-model="form.description" class="input-modern bg-slate-50 border-slate-200"></div>
                                            </div>
                                        </div>

                                        <div>
                                            <h3 class="text-sm font-bold text-slate-900 border-b border-slate-100 pb-2 mb-4"><i class="fa-solid fa-money-bill-wave text-emerald-500 mr-2"></i> Przychody i Koszty</h3>
                                            <div class="space-y-4">
                                                <div class="bg-emerald-50 p-4 rounded-xl border border-emerald-100">
                                                    <label class="block text-xs font-bold text-emerald-800 uppercase tracking-widest mb-1">PRZYCHÓD NETTO (PLN)</label>
                                                    <p class="text-[10px] text-emerald-600 mb-2">Kwota netto, na którą opiewa faktura dla klienta.</p>
                                                    <input type="number" step="0.01" v-model.number="form.revenue_net" required class="input-modern w-full font-black text-lg text-emerald-900 bg-white border-emerald-200 focus:border-emerald-500">
                                                </div>
                                                
                                                <div class="bg-rose-50 p-4 rounded-xl border border-rose-100 grid grid-cols-1 sm:grid-cols-2 gap-4">
                                                    <div class="sm:col-span-2">
                                                        <label class="block text-xs font-bold text-rose-800 uppercase tracking-widest mb-1">Poniesione Koszty (PLN)</label>
                                                        <p class="text-[10px] text-rose-600 mb-2">Faktury kosztowe, które odliczysz od tego zlecenia.</p>
                                                    </div>
                                                    <div>
                                                        <label class="block text-xs font-semibold text-rose-700 mb-1">Koszty NETTO</label>
                                                        <input type="number" step="0.01" v-model.number="form.cost_net" required class="input-modern font-bold text-rose-900 bg-white border-rose-200 focus:border-rose-500">
                                                    </div>
                                                    <div>
                                                        <label class="block text-xs font-semibold text-rose-700 mb-1">Koszty BRUTTO</label>
                                                        <input type="number" step="0.01" v-model.number="form.cost_gross" required class="input-modern font-bold text-rose-900 bg-white border-rose-200 focus:border-rose-500">
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <button type="submit" class="btn-primary w-full py-4 text-sm tracking-widest uppercase shadow-lg shadow-sky-500/30">
                                            Zapisz Kalkulację do Bazy
                                        </button>
                                    </form>
                                </div>

                                <!-- Kalkulator na żywo (Prawy Panel) -->
                                <div class="lg:col-span-5">
                                    <div class="glass-panel bg-slate-900 text-white overflow-hidden shadow-2xl sticky top-24">
                                        <div class="bg-slate-950 p-6 border-b border-slate-800">
                                            <h2 class="text-sm font-black uppercase tracking-widest text-sky-400 mb-1"><i class="fa-solid fa-bolt mr-2"></i> Kalkulacja na żywo</h2>
                                            <p class="text-xs text-slate-400">Oparta na ustawieniach globalnych: VAT {{ settings.vat_rate }}%, Pod. Doch. {{ settings.income_tax_rate }}%</p>
                                        </div>
                                        
                                        <div class="p-6 space-y-6">
                                            
                                            <!-- Podatek Dochodowy -->
                                            <div>
                                                <div class="flex justify-between items-end mb-1">
                                                    <span class="text-xs font-semibold text-slate-400">Dochód (Baza opodatkowania)</span>
                                                    <span class="text-sm font-bold">{{ formatCurrency(liveCalc.income) }}</span>
                                                </div>
                                                <div class="flex justify-between items-end pb-3 border-b border-slate-800">
                                                    <span class="text-xs font-semibold text-rose-400">Podatek Dochodowy ({{ settings.income_tax_rate }}%)</span>
                                                    <span class="text-base font-bold text-rose-400">- {{ formatCurrency(liveCalc.income_tax) }}</span>
                                                </div>
                                            </div>
                                            
                                            <!-- VAT -->
                                            <div>
                                                <div class="flex justify-between items-end mb-1">
                                                    <span class="text-xs font-semibold text-slate-400">VAT Należny (Z przychodu)</span>
                                                    <span class="text-xs font-medium text-slate-300">{{ formatCurrency(liveCalc.vat_należny) }}</span>
                                                </div>
                                                <div class="flex justify-between items-end mb-2">
                                                    <span class="text-xs font-semibold text-emerald-400">VAT Naliczony (Z kosztów)</span>
                                                    <span class="text-xs font-medium text-emerald-400">- {{ formatCurrency(liveCalc.vat_naliczony) }}</span>
                                                </div>
                                                <div class="flex justify-between items-end p-3 rounded-lg" :class="liveCalc.vat_to_pay >= 0 ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'">
                                                    <span class="text-xs font-bold uppercase tracking-wider">{{ liveCalc.vat_to_pay >= 0 ? 'VAT DO ZAPŁATY (US)' : 'VAT DO ZWROTU' }}</span>
                                                    <span class="text-lg font-black">{{ formatCurrency(Math.abs(liveCalc.vat_to_pay)) }}</span>
                                                </div>
                                            </div>
                                            
                                        </div>
                                        
                                        <!-- Wynik na rękę -->
                                        <div class="bg-gradient-to-r from-sky-600 to-blue-700 p-6 shadow-inner">
                                            <p class="text-[10px] font-black uppercase tracking-widest text-sky-200 mb-1">ZYSK NA CZYSTO (DO KIESZENI)</p>
                                            <p class="text-4xl font-black text-white">{{ formatCurrency(liveCalc.net_profit) }}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- TAB: ADMINISTRACJA -->
                        <div v-else-if="currentTab === 'admin'" class="max-w-3xl mx-auto space-y-6">
                            <div class="border-b border-slate-200 pb-4">
                                <h1 class="text-2xl font-bold text-slate-900">Administracja i Podatki</h1>
                                <p class="text-sm text-slate-500 mt-1">Globalne parametry służące do kalkulacji zysków.</p>
                            </div>
                            
                            <div class="glass-panel p-6 md:p-10 bg-white">
                                <form @submit.prevent="saveSettings" class="space-y-6">
                                    
                                    <div class="bg-slate-50 p-6 rounded-xl border border-slate-200">
                                        <h3 class="text-sm font-bold text-slate-900 mb-4 uppercase tracking-widest"><i class="fa-solid fa-landmark text-slate-400 mr-2"></i> Stawki Podatkowe</h3>
                                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            <div>
                                                <label class="block text-xs font-bold text-slate-600 mb-1">Podstawowa stawka VAT (%)</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.vat_rate" required class="input-modern w-full pr-8 font-bold text-slate-900">
                                                    <span class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 font-bold">%</span>
                                                </div>
                                            </div>
                                            <div>
                                                <label class="block text-xs font-bold text-slate-600 mb-1">Podatek Dochodowy (%)</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.income_tax_rate" required class="input-modern w-full pr-8 font-bold text-slate-900">
                                                    <span class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 font-bold">%</span>
                                                </div>
                                                <p class="text-[10px] text-slate-500 mt-1">np. 19% (Liniowy) lub 12% (Ryczałt)</p>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn-primary py-3 px-8 w-full sm:w-auto">Zapisz Ustawienia</button>
                                </form>
                            </div>
                        </div>
                    </transition>
                </main>
            </template>
        </div>

        <script>
            const { createApp } = Vue;
            createApp({
                data() {
                    return {
                        loginData: { username: '', password: '' },
                        token: localStorage.getItem('invoice_token') || null,
                        user: JSON.parse(localStorage.getItem('invoice_user')) || {},
                        currentTab: 'dashboard',
                        mobileMenuOpen: false,
                        toast: { show: false, message: '', type: 'success' },
                        
                        settings: { vat_rate: 23.0, income_tax_rate: 19.0 },
                        invoices: [],
                        
                        form: {
                            invoice_number: '',
                            issue_date: new Date().toISOString().split('T')[0],
                            client_name: '',
                            description: '',
                            revenue_net: 0,
                            cost_net: 0,
                            cost_gross: 0
                        }
                    }
                },
                computed: {
                    // Kalkulator na żywo na podstawie wpisanych danych i ustawień
                    liveCalc() {
                        const rev_net = Number(this.form.revenue_net) || 0;
                        const cost_net = Number(this.form.cost_net) || 0;
                        const cost_gross = Number(this.form.cost_gross) || 0;
                        const v_rate = Number(this.settings.vat_rate) / 100 || 0;
                        const t_rate = Number(this.settings.income_tax_rate) / 100 || 0;
                        
                        const income = rev_net - cost_net;
                        const income_tax = income > 0 ? income * t_rate : 0;
                        const net_profit = income - income_tax;
                        
                        const vat_należny = rev_net * v_rate;
                        const vat_naliczony = cost_gross - cost_net;
                        const vat_to_pay = vat_należny - vat_naliczony;
                        
                        return { income, income_tax, net_profit, vat_należny, vat_naliczony, vat_to_pay };
                    },
                    // Sumy dla dashboardu
                    totalRevenueNet() { return this.invoices.reduce((sum, inv) => sum + inv.revenue_net, 0); },
                    totalCostNet() { return this.invoices.reduce((sum, inv) => sum + inv.cost_net, 0); },
                    totalNetProfit() { return this.invoices.reduce((sum, inv) => sum + inv.calc_net_profit, 0); }
                },
                mounted() {
                    if (this.token) this.loadData();
                },
                methods: {
                    showToast(message, type = 'success') {
                        this.toast.message = message; this.toast.type = type; this.toast.show = true;
                        setTimeout(() => this.toast.show = false, 3500);
                    },
                    formatCurrency(value) {
                        return new Intl.NumberFormat('pl-PL', { style: 'currency', currency: 'PLN' }).format(value);
                    },
                    async api(endpoint, method = 'GET', body = null) {
                        const headers = { 'Authorization': 'Bearer ' + this.token };
                        if (body) {
                            headers['Content-Type'] = 'application/json';
                            body = JSON.stringify(body);
                        }
                        const res = await fetch('/api/' + endpoint, { method, headers, body });
                        const data = await res.json();
                        if (!res.ok) {
                            if (res.status === 401) this.logout();
                            throw new Error(data.detail || 'Błąd API');
                        }
                        return data;
                    },
                    async login() {
                        try {
                            const fd = new FormData();
                            fd.append('username', this.loginData.username);
                            fd.append('password', this.loginData.password);
                            const res = await fetch('/api/token', { method: 'POST', body: fd });
                            const data = await res.json();
                            if (!res.ok) throw new Error(data.detail);
                            
                            this.token = data.access_token;
                            this.user = { email: this.loginData.username, role: data.role };
                            localStorage.setItem('invoice_token', this.token);
                            localStorage.setItem('invoice_user', JSON.stringify(this.user));
                            this.loadData();
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    logout() {
                        this.token = null; this.user = {};
                        localStorage.removeItem('invoice_token'); localStorage.removeItem('invoice_user');
                    },
                    setTab(tab) {
                        this.currentTab = tab; this.mobileMenuOpen = false;
                        if(tab !== 'add_invoice') this.loadData();
                    },
                    async loadData() {
                        try {
                            this.settings = await this.api('settings');
                            this.invoices = await this.api('invoices');
                        } catch(e) { console.error(e); }
                    },
                    async saveSettings() {
                        try {
                            await this.api('settings', 'PUT', this.settings);
                            this.showToast("Stawki podatkowe zostały zaktualizowane.");
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async saveInvoice() {
                        try {
                            await this.api('invoices', 'POST', this.form);
                            this.showToast("Faktura z kalkulacją została zapisana!");
                            // Reset formularza
                            this.form = {
                                invoice_number: '', issue_date: new Date().toISOString().split('T')[0],
                                client_name: '', description: '', revenue_net: 0, cost_net: 0, cost_gross: 0
                            };
                            this.setTab('dashboard');
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async deleteInvoice(id) {
                        if(!confirm("Czy na pewno usunąć ten wpis?")) return;
                        try {
                            await this.api(`invoices/${id}`, 'DELETE');
                            this.invoices = this.invoices.filter(i => i.id !== id);
                            this.showToast("Usunięto fakturę z rejestru.");
                        } catch(e) { this.showToast(e.message, 'error'); }
                    }
                }
            }).mount('#app')
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
