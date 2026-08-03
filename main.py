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
SECRET_KEY = "super-secret-key-faktury-zyski-fintech"
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
    vat_rate = Column(Float, default=23.0)           
    income_tax_rate = Column(Float, default=19.0)    

class Invoice(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True, index=True)
    invoice_number = Column(String, unique=True, index=True, nullable=False)
    issue_date = Column(Date, nullable=False)
    client_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    
    revenue_net = Column(Float, nullable=False) 
    cost_net = Column(Float, nullable=False)    
    cost_gross = Column(Float, nullable=False)  
    
    applied_vat_rate = Column(Float, nullable=False)
    applied_tax_rate = Column(Float, nullable=False)
    
    calc_income = Column(Float, nullable=False)       
    calc_income_tax = Column(Float, nullable=False)   
    calc_vat_to_pay = Column(Float, nullable=False)   
    calc_net_profit = Column(Float, nullable=False)   
    
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
    
    # KONTO LOGOWANIA
    admin_email = "kh@orbis-software.pl"
    admin = db.query(User).filter(User.email == admin_email).first()
    if not admin:
        hashed = get_password_hash("Zyski123!")
        new_admin = User(email=admin_email, hashed_password=hashed, role="admin")
        db.add(new_admin)
        
    settings = db.query(AppSettings).first()
    if not settings:
        db.add(AppSettings(vat_rate=23.0, income_tax_rate=19.0))
    db.commit()
    db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(title="FinTech Analytics API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ==========================================
# 5. ENDPOINTY API
# ==========================================
@app.post("/api/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Odmowa dostępu. Błędne dane.")
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

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
    return {"msg": "Parametry podatkowe zaktualizowane."}

@app.get("/api/invoices", response_model=List[InvoiceResponse])
def get_invoices(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Invoice).order_by(Invoice.issue_date.desc(), Invoice.id.desc()).all()

@app.post("/api/invoices", response_model=InvoiceResponse)
def create_invoice(invoice: InvoiceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = db.query(AppSettings).first()
    vat_r = settings.vat_rate
    tax_r = settings.income_tax_rate
    
    income = invoice.revenue_net - invoice.cost_net
    income_tax = (income * (tax_r / 100)) if income > 0 else 0.0
    net_profit = income - income_tax
    
    vat_należny = invoice.revenue_net * (vat_r / 100) 
    vat_naliczony = invoice.cost_gross - invoice.cost_net 
    vat_to_pay = vat_należny - vat_naliczony 
    
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
    return {"msg": "Faktura wykasowana z rejestru."}

# ==========================================
# 6. FRONTEND (VUE 3 + TAILWIND) - DARK FINTECH
# ==========================================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    return """
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FINANCE TRACKER</title>
        <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
        <style>
            body { 
                font-family: 'Inter', sans-serif; 
                background-color: #09090b; /* zinc-950 */
                color: #fafafa; /* zinc-50 */
            }
            
            /* Klasa dla wszystkich cyfr i finansów */
            .font-mono {
                font-family: 'JetBrains Mono', monospace;
            }

            .fin-card {
                background: #18181b; /* zinc-900 */
                border: 1px solid #27272a; /* zinc-800 */
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
            }

            .fin-input {
                background: #09090b; /* zinc-950 */
                border: 1px solid #3f3f46; /* zinc-700 */
                border-radius: 8px;
                padding: 0.75rem 1rem;
                color: #f4f4f5;
                font-size: 0.875rem;
                transition: all 0.2s;
                width: 100%;
            }
            .fin-input:focus {
                outline: none;
                border-color: #10b981; /* emerald-500 */
                box-shadow: 0 0 0 1px #10b981;
            }
            .fin-input::placeholder { color: #52525b; } /* zinc-500 */

            .btn-primary {
                background: #10b981; /* emerald-500 */
                color: #022c22; /* emerald-950 */
                font-weight: 600;
                padding: 0.75rem 1.5rem;
                border-radius: 8px;
                transition: all 0.2s;
                border: none;
                display: flex; justify-content: center; align-items: center; gap: 0.5rem;
            }
            .btn-primary:hover { background: #34d399; } /* emerald-400 */
            .btn-primary:active { transform: translateY(1px); }

            .btn-secondary {
                background: transparent;
                border: 1px solid #3f3f46;
                color: #e4e4e7;
                padding: 0.75rem 1.5rem;
                border-radius: 8px;
                font-weight: 500;
                transition: all 0.2s;
            }
            .btn-secondary:hover { background: #27272a; color: #fff; }

            .nav-item {
                display: flex; align-items: center; gap: 0.75rem;
                padding: 0.875rem 1.25rem;
                border-radius: 8px;
                font-size: 0.875rem;
                font-weight: 500;
                color: #a1a1aa; /* zinc-400 */
                transition: all 0.2s;
                border-left: 3px solid transparent;
            }
            .nav-item:hover { color: #fafafa; background: #27272a; }
            .nav-item.active { 
                color: #10b981; 
                background: #022c22; /* emerald-950 */
                border-left-color: #10b981;
            }

            /* Custom scrollbar for dark theme */
            ::-webkit-scrollbar { width: 8px; height: 8px; }
            ::-webkit-scrollbar-track { background: #09090b; }
            ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: #52525b; }

            .fade-enter-active, .fade-leave-active { transition: opacity 0.2s; }
            .fade-enter-from, .fade-leave-to { opacity: 0; }
        </style>
    </head>
    <body class="flex flex-col md:flex-row h-screen overflow-hidden">
        <div id="app" class="h-full w-full flex relative">
            
            <!-- TOAST -->
            <transition name="fade">
                <div v-if="toast.show" class="fixed top-6 right-6 z-[100] px-5 py-3 fin-card border-l-4 shadow-2xl flex items-center gap-3 text-sm font-medium"
                     :class="toast.type === 'error' ? 'border-rose-500 text-rose-100' : 'border-emerald-500 text-emerald-100'">
                    <i class="fa-solid" :class="toast.type === 'error' ? 'fa-circle-exclamation text-rose-500' : 'fa-circle-check text-emerald-500'"></i>
                    {{ toast.message }}
                </div>
            </transition>

            <!-- Ekran logowania -->
            <div v-if="!token" class="flex-1 flex flex-col items-center justify-center p-4">
                <div class="w-full max-w-sm">
                    <div class="mb-10 text-center">
                        <i class="fa-solid fa-layer-group text-4xl text-emerald-500 mb-4"></i>
                        <h2 class="text-2xl font-semibold tracking-tight text-white">FINANCE TRACKER</h2>
                        <p class="text-xs text-zinc-500 mt-2 uppercase tracking-widest">Autoryzacja dostępu</p>
                    </div>
                    <div class="fin-card p-8">
                        <form @submit.prevent="login" class="space-y-5">
                            <div>
                                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Adres E-mail</label>
                                <input type="email" v-model="loginData.username" required class="fin-input font-mono" placeholder="sys@admin.com">
                            </div>
                            <div>
                                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Hasło Główne</label>
                                <input type="password" v-model="loginData.password" required class="fin-input font-mono">
                            </div>
                            <button type="submit" class="btn-primary w-full mt-4 py-3 text-sm uppercase tracking-wider font-bold">Połącz z systemem</button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Główna Aplikacja -->
            <template v-else>
                
                <!-- Sidebar (Desktop) -->
                <div class="hidden md:flex flex-col w-64 bg-[#09090b] border-r border-zinc-800 z-20 h-full flex-shrink-0">
                    <div class="p-6 border-b border-zinc-800 flex items-center gap-3">
                        <div class="w-8 h-8 rounded bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center text-emerald-500">
                            <i class="fa-solid fa-chart-line"></i>
                        </div>
                        <div>
                            <h1 class="text-sm font-bold text-white tracking-tight leading-none">FINANCE<br><span class="text-emerald-500">TRACKER</span></h1>
                        </div>
                    </div>
                    <nav class="flex-1 px-3 py-6 space-y-2 overflow-y-auto">
                        <button @click="setTab('dashboard')" class="nav-item w-full" :class="currentTab==='dashboard' ? 'active' : ''">
                            <i class="fa-solid fa-table-list w-5 text-center"></i> Rejestr Finansowy
                        </button>
                        <button @click="setTab('add_invoice')" class="nav-item w-full" :class="currentTab==='add_invoice' ? 'active' : ''">
                            <i class="fa-solid fa-calculator w-5 text-center"></i> Analiza Faktury
                        </button>
                        <button v-if="user.role === 'admin'" @click="setTab('admin')" class="nav-item w-full" :class="currentTab==='admin' ? 'active' : ''">
                            <i class="fa-solid fa-sliders w-5 text-center"></i> Parametry Systemu
                        </button>
                    </nav>
                    <div class="p-4 border-t border-zinc-800 bg-zinc-900/50">
                        <div class="flex items-center gap-3 mb-4 px-2">
                            <div class="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-400">
                                {{ user.email.charAt(0).toUpperCase() }}
                            </div>
                            <div class="overflow-hidden">
                                <p class="text-xs font-medium text-zinc-300 truncate">{{ user.email }}</p>
                                <p class="text-[9px] text-zinc-500 uppercase tracking-widest">{{ user.role }}</p>
                            </div>
                        </div>
                        <button @click="logout" class="btn-secondary w-full text-xs py-2">Zakończ sesję</button>
                    </div>
                </div>

                <!-- Mobile Header -->
                <div class="md:hidden fixed top-0 w-full bg-[#09090b] z-50 flex justify-between items-center p-4 border-b border-zinc-800">
                    <div class="flex items-center gap-2">
                        <i class="fa-solid fa-chart-line text-emerald-500"></i>
                        <span class="font-bold text-sm text-white">FINANCE TRACKER</span>
                    </div>
                    <button @click="mobileMenuOpen = !mobileMenuOpen" class="text-zinc-400 p-1"><i class="fa-solid fa-bars text-lg"></i></button>
                </div>
                
                <!-- Mobile Dropdown -->
                <transition name="fade">
                    <div v-if="mobileMenuOpen" class="md:hidden fixed top-[53px] left-0 w-full bg-[#18181b] z-40 p-4 space-y-2 border-b border-zinc-800 shadow-2xl">
                        <button @click="setTab('dashboard')" class="nav-item w-full" :class="currentTab==='dashboard' ? 'active' : ''">Rejestr Finansowy</button>
                        <button @click="setTab('add_invoice')" class="nav-item w-full" :class="currentTab==='add_invoice' ? 'active' : ''">Analiza Faktury</button>
                        <button v-if="user.role === 'admin'" @click="setTab('admin')" class="nav-item w-full" :class="currentTab==='admin' ? 'active' : ''">Parametry Systemu</button>
                        <hr class="border-zinc-800 my-2">
                        <button @click="logout" class="nav-item w-full text-rose-500 hover:text-rose-400">Zakończ sesję</button>
                    </div>
                </transition>

                <!-- MAIN CONTENT AREA -->
                <main class="flex-1 overflow-y-auto w-full pt-20 md:pt-0 p-4 md:p-8 z-10 bg-[#09090b]">
                    <transition name="fade" mode="out-in">
                        
                        <!-- TAB: BAZA FAKTUR -->
                        <div v-if="currentTab === 'dashboard'" class="max-w-7xl mx-auto space-y-8">
                            
                            <div>
                                <h1 class="text-2xl font-semibold text-white tracking-tight">Analityka Portfela</h1>
                                <p class="text-sm text-zinc-500 mt-1">Zestawienie przychodów, kosztów i realnego zysku netto.</p>
                            </div>
                            
                            <!-- Podsumowanie finansowe -->
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                <div class="fin-card p-5 border-l-2 border-l-blue-500">
                                    <p class="text-xs font-medium text-zinc-400 uppercase tracking-widest mb-2">Przychód Netto</p>
                                    <p class="text-2xl font-mono font-bold text-white">{{ formatCurrency(totalRevenueNet) }}</p>
                                </div>
                                <div class="fin-card p-5 border-l-2 border-l-rose-500">
                                    <p class="text-xs font-medium text-zinc-400 uppercase tracking-widest mb-2">Koszty Netto</p>
                                    <p class="text-2xl font-mono font-bold text-white">{{ formatCurrency(totalCostNet) }}</p>
                                </div>
                                <div class="fin-card p-5 bg-emerald-500/10 border border-emerald-500/20">
                                    <p class="text-xs font-medium text-emerald-500 uppercase tracking-widest mb-2">Zysk Netto (Czysty)</p>
                                    <p class="text-3xl font-mono font-bold text-emerald-400">{{ formatCurrency(totalNetProfit) }}</p>
                                </div>
                            </div>

                            <!-- Tabela -->
                            <div class="fin-card overflow-x-auto">
                                <table class="w-full text-left whitespace-nowrap">
                                    <thead class="bg-zinc-900/50 border-b border-zinc-800">
                                        <tr>
                                            <th class="px-5 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider">Dokument</th>
                                            <th class="px-5 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider">Data</th>
                                            <th class="px-5 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider text-right">Przychód</th>
                                            <th class="px-5 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider text-right">Koszt</th>
                                            <th class="px-5 py-4 text-xs font-medium text-emerald-500 uppercase tracking-wider text-right">Zysk Na Czysto</th>
                                            <th class="px-5 py-4 text-center"></th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-zinc-800/50">
                                        <tr v-for="inv in invoices" :key="inv.id" class="hover:bg-zinc-800/30 transition">
                                            <td class="px-5 py-4">
                                                <div class="font-medium text-zinc-200">{{ inv.invoice_number }}</div>
                                                <div class="text-xs text-zinc-500 mt-0.5">{{ inv.client_name }}</div>
                                            </td>
                                            <td class="px-5 py-4 text-sm text-zinc-400 font-mono">{{ inv.issue_date }}</td>
                                            <td class="px-5 py-4 text-sm font-mono text-zinc-300 text-right">{{ formatCurrency(inv.revenue_net) }}</td>
                                            <td class="px-5 py-4 text-sm font-mono text-rose-400/80 text-right">{{ formatCurrency(inv.cost_net) }}</td>
                                            <td class="px-5 py-4 text-base font-mono font-bold text-emerald-400 text-right">{{ formatCurrency(inv.calc_net_profit) }}</td>
                                            <td class="px-5 py-4 text-center">
                                                <button @click="deleteInvoice(inv.id)" class="text-zinc-600 hover:text-rose-500 transition px-2 py-1"><i class="fa-solid fa-trash"></i></button>
                                            </td>
                                        </tr>
                                        <tr v-if="invoices.length === 0">
                                            <td colspan="6" class="py-12 text-center text-sm text-zinc-600">Brak danych finansowych w rejestrze.</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- TAB: DODAWANIE (KALKULATOR NA ŻYWO) -->
                        <div v-else-if="currentTab === 'add_invoice'" class="max-w-7xl mx-auto space-y-6">
                            
                            <div class="border-b border-zinc-800 pb-4">
                                <h1 class="text-2xl font-semibold text-white tracking-tight">Kalkulator Marginesu</h1>
                                <p class="text-sm text-zinc-500 mt-1">Wprowadź dane zlecenia. System natychmiast wyliczy obciążenia i zysk bazując na aktualnych parametrach.</p>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                                
                                <!-- Formularz Wprowadzania -->
                                <div class="lg:col-span-7 space-y-6">
                                    <form @submit.prevent="saveInvoice" class="fin-card p-6 md:p-8 space-y-8">
                                        
                                        <div>
                                            <h3 class="text-xs font-bold text-zinc-400 uppercase tracking-widest mb-4 flex items-center gap-2"><i class="fa-solid fa-file-invoice"></i> Metadane Dokumentu</h3>
                                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
                                                <div><label class="block text-xs font-medium text-zinc-400 mb-1.5">Numer Faktury</label><input type="text" v-model="form.invoice_number" required class="fin-input font-mono"></div>
                                                <div><label class="block text-xs font-medium text-zinc-400 mb-1.5">Data Wystawienia</label><input type="date" v-model="form.issue_date" required class="fin-input font-mono text-zinc-300"></div>
                                                <div class="sm:col-span-2"><label class="block text-xs font-medium text-zinc-400 mb-1.5">Nabywca (Klient)</label><input type="text" v-model="form.client_name" required class="fin-input"></div>
                                            </div>
                                        </div>

                                        <div class="pt-2">
                                            <h3 class="text-xs font-bold text-emerald-500 uppercase tracking-widest mb-4 flex items-center gap-2"><i class="fa-solid fa-coins"></i> Wartości Finansowe</h3>
                                            
                                            <div class="space-y-5">
                                                <div>
                                                    <label class="block text-xs font-medium text-zinc-400 mb-1.5">Przychód Netto (PLN)</label>
                                                    <input type="number" step="0.01" v-model.number="form.revenue_net" required class="fin-input font-mono text-lg text-emerald-400">
                                                </div>
                                                
                                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-5 p-4 bg-zinc-950/50 rounded-lg border border-zinc-800/50">
                                                    <div>
                                                        <label class="block text-xs font-medium text-zinc-400 mb-1.5">Koszty Poniesione NETTO</label>
                                                        <input type="number" step="0.01" v-model.number="form.cost_net" required class="fin-input font-mono text-rose-400">
                                                    </div>
                                                    <div>
                                                        <label class="block text-xs font-medium text-zinc-400 mb-1.5">Koszty Poniesione BRUTTO</label>
                                                        <input type="number" step="0.01" v-model.number="form.cost_gross" required class="fin-input font-mono text-rose-400">
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div class="pt-4 border-t border-zinc-800">
                                            <button type="submit" class="btn-primary w-full py-3 text-sm tracking-widest uppercase">Zapisz Operację do Bazy</button>
                                        </div>
                                    </form>
                                </div>

                                <!-- Kalkulator na żywo (TERMINAL STYLE) -->
                                <div class="lg:col-span-5 sticky top-24">
                                    <div class="fin-card bg-[#050505] overflow-hidden border-zinc-800">
                                        <div class="p-5 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/30">
                                            <span class="text-xs font-bold text-zinc-400 uppercase tracking-widest">Live Output</span>
                                            <div class="flex gap-2 text-[10px] font-mono text-zinc-500">
                                                <span class="bg-zinc-800 px-1.5 py-0.5 rounded">VAT: {{settings.vat_rate}}%</span>
                                                <span class="bg-zinc-800 px-1.5 py-0.5 rounded">PIT: {{settings.income_tax_rate}}%</span>
                                            </div>
                                        </div>
                                        
                                        <div class="p-6 font-mono text-sm space-y-5">
                                            
                                            <div class="space-y-2">
                                                <div class="flex justify-between text-zinc-400"><span>Baza opodatkowania (Dochód)</span> <span>{{ formatCurrency(liveCalc.income) }}</span></div>
                                                <div class="flex justify-between text-rose-400/80"><span>Podatek Dochodowy (PIT)</span> <span>-{{ formatCurrency(liveCalc.income_tax) }}</span></div>
                                            </div>
                                            
                                            <div class="h-px bg-zinc-800 border-none w-full"></div>
                                            
                                            <div class="space-y-2">
                                                <div class="flex justify-between text-zinc-400"><span>VAT Należny (od przychodu)</span> <span>{{ formatCurrency(liveCalc.vat_należny) }}</span></div>
                                                <div class="flex justify-between text-emerald-500/80"><span>VAT Naliczony (z kosztów)</span> <span>-{{ formatCurrency(liveCalc.vat_naliczony) }}</span></div>
                                                
                                                <div class="flex justify-between items-center mt-3 pt-3 border-t border-dashed border-zinc-800 text-sm font-bold" :class="liveCalc.vat_to_pay >= 0 ? 'text-amber-500' : 'text-blue-400'">
                                                    <span>{{ liveCalc.vat_to_pay >= 0 ? 'VAT do Urzędu Skarbowego' : 'Nadwyżka VAT (do zwrotu)' }}</span>
                                                    <span>{{ formatCurrency(Math.abs(liveCalc.vat_to_pay)) }}</span>
                                                </div>
                                            </div>
                                            
                                        </div>
                                        
                                        <!-- Wynik na rękę -->
                                        <div class="p-6 bg-emerald-500/10 border-t border-emerald-500/20">
                                            <p class="text-[10px] font-medium text-emerald-500 uppercase tracking-widest mb-1">Zysk Netto (Po opodatkowaniu)</p>
                                            <p class="text-4xl font-mono font-bold text-emerald-400">{{ formatCurrency(liveCalc.net_profit) }}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- TAB: ADMINISTRACJA -->
                        <div v-else-if="currentTab === 'admin'" class="max-w-3xl mx-auto space-y-6">
                            <div class="border-b border-zinc-800 pb-4">
                                <h1 class="text-2xl font-semibold text-white tracking-tight">Parametry Systemowe</h1>
                                <p class="text-sm text-zinc-500 mt-1">Ustawienia globalne stawek podatkowych dla nowych kalkulacji.</p>
                            </div>
                            
                            <div class="fin-card p-6 md:p-8">
                                <form @submit.prevent="saveSettings" class="space-y-6">
                                    
                                    <div>
                                        <h3 class="text-xs font-bold text-zinc-400 uppercase tracking-widest mb-4"><i class="fa-solid fa-percent mr-2"></i> Stawki Główne</h3>
                                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-5 p-5 bg-zinc-950/50 rounded-lg border border-zinc-800/50">
                                            <div>
                                                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Podstawowa stawka VAT</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.vat_rate" required class="fin-input font-mono pr-8 text-lg">
                                                    <span class="absolute right-3 top-1/2 -translate-y-1/2 font-mono text-zinc-500">%</span>
                                                </div>
                                            </div>
                                            <div>
                                                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Podatek Dochodowy (PIT)</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.income_tax_rate" required class="fin-input font-mono pr-8 text-lg">
                                                    <span class="absolute right-3 top-1/2 -translate-y-1/2 font-mono text-zinc-500">%</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn-primary w-full sm:w-auto py-3 text-sm tracking-widest uppercase px-8">Aktualizuj Parametry</button>
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
                        token: localStorage.getItem('fintech_token') || null,
                        user: JSON.parse(localStorage.getItem('fintech_user')) || {},
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
                            revenue_net: '',
                            cost_net: '',
                            cost_gross: ''
                        }
                    }
                },
                computed: {
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
                            throw new Error(data.detail || 'BŁĄD Z SERWERA');
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
                            localStorage.setItem('fintech_token', this.token);
                            localStorage.setItem('fintech_user', JSON.stringify(this.user));
                            this.loadData();
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    logout() {
                        this.token = null; this.user = {};
                        localStorage.removeItem('fintech_token'); localStorage.removeItem('fintech_user');
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
                            this.showToast("Parametry systemu zostały zapisane.");
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async saveInvoice() {
                        try {
                            const payload = {...this.form};
                            payload.revenue_net = Number(payload.revenue_net) || 0;
                            payload.cost_net = Number(payload.cost_net) || 0;
                            payload.cost_gross = Number(payload.cost_gross) || 0;

                            await this.api('invoices', 'POST', payload);
                            this.showToast("Analiza zapisana w rejestrze.");
                            this.form = {
                                invoice_number: '', issue_date: new Date().toISOString().split('T')[0],
                                client_name: '', description: '', revenue_net: '', cost_net: '', cost_gross: ''
                            };
                            this.setTab('dashboard');
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async deleteInvoice(id) {
                        if(!confirm("Czy na pewno wykasować tę pozycję z rejestru?")) return;
                        try {
                            await this.api(`invoices/${id}`, 'DELETE');
                            this.invoices = this.invoices.filter(i => i.id !== id);
                            this.showToast("Pozycja usunięta pomyślnie.");
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
