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
SECRET_KEY = "super-secret-key-faktury-zyski-brutal"
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
    
    # NOWE DANE LOGOWANIA
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

app = FastAPI(title="Neobrutal Finance API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ==========================================
# 5. ENDPOINTY API
# ==========================================
@app.post("/api/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="BŁĘDNY E-MAIL LUB HASŁO!")
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
    return {"msg": "USTAWIENIA ZAPISANE"}

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
    return {"msg": "FAKTURA USUNIĘTA"}

# ==========================================
# 6. FRONTEND NEOBRUTALISM (VUE 3 + TAILWIND)
# ==========================================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    return """
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ZYSKOMIERZ 3000</title>
        <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700;800&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #f4f4f0;
                --border-color: #000000;
                --primary: #facc15; /* Yellow */
                --secondary: #ff90e8; /* Pink */
                --accent: #06b6d4; /* Cyan */
                --success: #4ade80; /* Lime */
                --card-bg: #ffffff;
            }
            
            body { 
                font-family: 'Space Grotesk', sans-serif; 
                background-color: var(--bg); 
                color: #000; 
                /* Opcjonalny lekki pattern */
                background-image: radial-gradient(#000000 1px, transparent 1px);
                background-size: 40px 40px;
                background-position: -19px -19px;
            }
            
            /* KLASY NEOBRUTALISTYCZNE */
            .brutal-border {
                border: 3px solid var(--border-color);
            }
            
            .brutal-card {
                background: var(--card-bg);
                border: 3px solid var(--border-color);
                border-radius: 8px;
                box-shadow: 6px 6px 0px 0px var(--border-color);
            }

            .brutal-input {
                background: #fff;
                border: 3px solid var(--border-color);
                border-radius: 6px;
                padding: 0.75rem 1rem;
                font-weight: 700;
                font-size: 1rem;
                color: #000;
                transition: all 0.1s;
                box-shadow: inset 2px 2px 0px rgba(0,0,0,0.1);
            }
            .brutal-input:focus {
                outline: none;
                background: #fef08a; /* jasny żółty */
            }

            .brutal-btn {
                background: var(--primary);
                border: 3px solid var(--border-color);
                border-radius: 6px;
                font-weight: 800;
                font-size: 1rem;
                text-transform: uppercase;
                padding: 0.75rem 1.5rem;
                box-shadow: 4px 4px 0px 0px var(--border-color);
                transition: transform 0.1s, box-shadow 0.1s;
                cursor: pointer;
                color: #000;
                display: inline-flex; justify-content: center; align-items: center; gap: 0.5rem;
            }
            .brutal-btn:hover { background: #eab308; }
            .brutal-btn:active {
                transform: translate(4px, 4px);
                box-shadow: 0px 0px 0px 0px var(--border-color);
            }
            
            .brutal-btn-pink { background: var(--secondary); }
            .brutal-btn-pink:hover { background: #f472b6; }
            
            .brutal-btn-cyan { background: var(--accent); color: #fff;}
            .brutal-btn-cyan:hover { background: #0891b2; }

            .nav-item {
                display: flex; align-items: center; gap: 0.75rem;
                padding: 1rem;
                border: 3px solid transparent;
                border-radius: 8px;
                font-size: 1.1rem;
                font-weight: 800;
                color: #000;
                text-transform: uppercase;
                transition: all 0.1s;
            }
            .nav-item:hover { border-color: #000; background: #fff; }
            .nav-item.active { border-color: #000; background: var(--primary); box-shadow: 4px 4px 0px #000; }

            /* Tabela Brutal */
            .brutal-table-wrapper {
                border: 3px solid #000;
                border-radius: 8px;
                background: #fff;
                overflow-x: auto;
                box-shadow: 6px 6px 0px #000;
            }
            .brutal-table th { border-bottom: 3px solid #000; padding: 1rem; font-weight: 800; text-transform: uppercase; }
            .brutal-table td { border-bottom: 2px solid #000; padding: 1rem; font-weight: 600; }
            .brutal-table tr:last-child td { border-bottom: none; }
            .brutal-table tbody tr:hover { background: #fef08a; }

            /* Animacje Vue */
            .fade-enter-active, .fade-leave-active { transition: opacity 0.2s; }
            .fade-enter-from, .fade-leave-to { opacity: 0; }
        </style>
    </head>
    <body class="flex flex-col h-screen overflow-hidden">
        <div id="app" class="h-full w-full flex flex-col relative">
            
            <!-- TOAST -->
            <transition name="fade">
                <div v-if="toast.show" class="fixed top-6 right-6 z-[100] px-6 py-4 brutal-card flex items-center gap-3 font-black text-lg"
                     :class="toast.type === 'error' ? 'bg-rose-400' : 'bg-green-400'">
                    <i class="fa-solid" :class="toast.type === 'error' ? 'fa-skull' : 'fa-bolt'"></i>
                    {{ toast.message }}
                </div>
            </transition>

            <!-- Ekran logowania -->
            <div v-if="!token" class="flex-1 flex flex-col items-center justify-center p-4">
                <div class="w-full max-w-sm">
                    <div class="mb-8 text-center bg-black text-white brutal-card border-black p-4 rotate-[-2deg] mx-auto w-fit">
                        <h2 class="text-3xl font-black tracking-tighter uppercase">ZYSKOMIERZ<br>RADAR</h2>
                    </div>
                    <div class="brutal-card p-8 bg-white">
                        <form @submit.prevent="login" class="space-y-5">
                            <div>
                                <label class="block text-sm font-black uppercase mb-1">IDENTYFIKATOR (EMAIL)</label>
                                <input type="email" v-model="loginData.username" required class="brutal-input w-full">
                            </div>
                            <div>
                                <label class="block text-sm font-black uppercase mb-1">KOD DOSTĘPU</label>
                                <input type="password" v-model="loginData.password" required class="brutal-input w-full">
                            </div>
                            <button type="submit" class="brutal-btn w-full mt-4 py-4 text-xl">WEJDŹ <i class="fa-solid fa-arrow-right"></i></button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Główna Aplikacja (Top Navbar + Content) -->
            <template v-else>
                
                <!-- TOP NAVBAR NEOBRUTAL -->
                <header class="bg-white border-b-[4px] border-black flex justify-between items-center p-4 z-40 sticky top-0">
                    <div class="flex items-center gap-4">
                        <div class="bg-black text-yellow-400 px-3 py-1 border-[3px] border-black font-black text-xl italic tracking-tighter uppercase transform -skew-x-6 hidden sm:block">
                            ZYSKOMIERZ
                        </div>
                        
                        <!-- Desktop Nav -->
                        <nav class="hidden md:flex gap-2 ml-4">
                            <button @click="currentTab = 'dashboard'" class="brutal-btn" :class="currentTab==='dashboard' ? 'bg-cyan-400' : 'bg-white shadow-none'">Baza Faktur</button>
                            <button @click="currentTab = 'add_invoice'" class="brutal-btn" :class="currentTab==='add_invoice' ? 'bg-pink-400' : 'bg-white shadow-none'">Kalkulator</button>
                            <button v-if="user.role === 'admin'" @click="currentTab = 'admin'" class="brutal-btn" :class="currentTab==='admin' ? 'bg-yellow-400' : 'bg-white shadow-none'"><i class="fa-solid fa-gear"></i></button>
                        </nav>
                    </div>

                    <div class="flex items-center gap-4">
                        <div class="hidden sm:block text-right">
                            <p class="font-black text-sm uppercase">{{ user.email }}</p>
                            <p class="text-[10px] font-bold bg-black text-white px-1 inline-block uppercase">{{ user.role }}</p>
                        </div>
                        <button @click="logout" class="brutal-btn bg-white hover:bg-rose-400 py-2 px-3 shadow-none border-2"><i class="fa-solid fa-power-off"></i></button>
                        
                        <!-- Mobile Toggle -->
                        <button class="md:hidden brutal-btn bg-yellow-400 py-2 px-3" @click="mobileMenuOpen = !mobileMenuOpen"><i class="fa-solid fa-bars"></i></button>
                    </div>
                </header>
                
                <!-- Mobile Dropdown -->
                <div v-if="mobileMenuOpen" class="md:hidden bg-white border-b-[4px] border-black p-4 space-y-3 z-30 relative shadow-[0px_10px_0px_rgba(0,0,0,1)]">
                    <button @click="setTab('dashboard')" class="brutal-btn w-full" :class="currentTab==='dashboard' ? 'bg-cyan-400' : 'bg-white'">Baza Faktur</button>
                    <button @click="setTab('add_invoice')" class="brutal-btn w-full" :class="currentTab==='add_invoice' ? 'bg-pink-400' : 'bg-white'">Kalkulator Zysku</button>
                    <button v-if="user.role === 'admin'" @click="setTab('admin')" class="brutal-btn w-full" :class="currentTab==='admin' ? 'bg-yellow-400' : 'bg-white'">Administracja</button>
                </div>

                <!-- MAIN CONTENT AREA -->
                <main class="flex-1 overflow-y-auto w-full p-4 md:p-8 z-10">
                    <transition name="fade" mode="out-in">
                        
                        <!-- TAB: BAZA FAKTUR -->
                        <div v-if="currentTab === 'dashboard'" class="max-w-7xl mx-auto space-y-8">
                            
                            <div>
                                <h1 class="text-4xl md:text-5xl font-black uppercase tracking-tighter drop-shadow-[2px_2px_0px_#000] text-white">REJESTR FAKTUR</h1>
                            </div>
                            
                            <!-- Podsumowanie finansowe -->
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-6">
                                <div class="brutal-card p-6 bg-cyan-400">
                                    <p class="font-black text-black uppercase mb-1">Przychód Netto</p>
                                    <p class="text-3xl font-black bg-white inline-block px-2 border-2 border-black">{{ formatCurrency(totalRevenueNet) }}</p>
                                </div>
                                <div class="brutal-card p-6 bg-rose-400">
                                    <p class="font-black text-black uppercase mb-1">Koszty Netto</p>
                                    <p class="text-3xl font-black bg-white inline-block px-2 border-2 border-black">{{ formatCurrency(totalCostNet) }}</p>
                                </div>
                                <div class="brutal-card p-6 bg-lime-400 transform sm:-translate-y-2 sm:rotate-2">
                                    <p class="font-black text-black uppercase mb-1"><i class="fa-solid fa-money-bill-wave"></i> CZYSTY ZYSK</p>
                                    <p class="text-4xl font-black bg-black text-lime-400 inline-block px-3 py-1">{{ formatCurrency(totalNetProfit) }}</p>
                                </div>
                            </div>

                            <!-- Tabela -->
                            <div class="brutal-table-wrapper">
                                <table class="w-full text-left brutal-table whitespace-nowrap">
                                    <thead class="bg-yellow-400">
                                        <tr>
                                            <th>Numer / Klient</th>
                                            <th>Data</th>
                                            <th class="text-right">Przychód</th>
                                            <th class="text-right">Koszt</th>
                                            <th class="text-right bg-black text-white">Zysk Na Czysto</th>
                                            <th class="text-center">Del</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for="inv in invoices" :key="inv.id">
                                            <td>
                                                <div class="font-black text-lg">{{ inv.invoice_number }}</div>
                                                <div class="text-sm">{{ inv.client_name }}</div>
                                            </td>
                                            <td>{{ inv.issue_date }}</td>
                                            <td class="text-right font-black text-cyan-600">{{ formatCurrency(inv.revenue_net) }}</td>
                                            <td class="text-right font-black text-rose-600">{{ formatCurrency(inv.cost_net) }}</td>
                                            <td class="text-right text-xl font-black bg-lime-200 border-l-3 border-black">{{ formatCurrency(inv.calc_net_profit) }}</td>
                                            <td class="text-center">
                                                <button @click="deleteInvoice(inv.id)" class="bg-black text-white px-3 py-1 font-black hover:bg-rose-500 hover:text-black border-2 border-transparent transition">X</button>
                                            </td>
                                        </tr>
                                        <tr v-if="invoices.length === 0">
                                            <td colspan="6" class="py-12 text-center font-black uppercase text-xl bg-gray-100">Baza jest pusta. Dodaj fakturę!</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- TAB: DODAWANIE (KALKULATOR NA ŻYWO) -->
                        <div v-else-if="currentTab === 'add_invoice'" class="max-w-7xl mx-auto space-y-6">
                            
                            <div>
                                <h1 class="text-4xl md:text-5xl font-black uppercase tracking-tighter drop-shadow-[2px_2px_0px_#000] text-white">KALKULATOR</h1>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                                
                                <!-- Formularz Wprowadzania -->
                                <div class="lg:col-span-7 space-y-6">
                                    <form @submit.prevent="saveInvoice" class="brutal-card p-6 md:p-8 space-y-6 bg-white">
                                        
                                        <div class="bg-gray-100 p-4 border-[3px] border-black">
                                            <h3 class="font-black uppercase text-xl mb-4 bg-black text-white inline-block px-2">DANE FAKTURY</h3>
                                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                                <div><label class="block font-black uppercase mb-1">Numer</label><input type="text" v-model="form.invoice_number" required class="brutal-input w-full"></div>
                                                <div><label class="block font-black uppercase mb-1">Data</label><input type="date" v-model="form.issue_date" required class="brutal-input w-full"></div>
                                                <div class="sm:col-span-2"><label class="block font-black uppercase mb-1">Klient</label><input type="text" v-model="form.client_name" required class="brutal-input w-full"></div>
                                            </div>
                                        </div>

                                        <div class="bg-gray-100 p-4 border-[3px] border-black space-y-4">
                                            <h3 class="font-black uppercase text-xl bg-black text-white inline-block px-2">KWOTY (PLN)</h3>
                                            
                                            <div class="bg-cyan-200 p-4 border-[3px] border-black">
                                                <label class="block font-black uppercase mb-1 text-xl">Przychód Netto</label>
                                                <input type="number" step="0.01" v-model.number="form.revenue_net" required class="brutal-input w-full text-2xl font-black">
                                            </div>
                                            
                                            <div class="bg-pink-200 p-4 border-[3px] border-black grid grid-cols-1 sm:grid-cols-2 gap-4">
                                                <div class="sm:col-span-2">
                                                    <label class="block font-black uppercase mb-1 text-xl">Koszty poniesione</label>
                                                </div>
                                                <div>
                                                    <label class="block font-black uppercase mb-1 text-sm">Koszty NETTO</label>
                                                    <input type="number" step="0.01" v-model.number="form.cost_net" required class="brutal-input w-full">
                                                </div>
                                                <div>
                                                    <label class="block font-black uppercase mb-1 text-sm">Koszty BRUTTO</label>
                                                    <input type="number" step="0.01" v-model.number="form.cost_gross" required class="brutal-input w-full">
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <button type="submit" class="brutal-btn brutal-btn-pink w-full py-4 text-2xl">
                                            <i class="fa-solid fa-floppy-disk"></i> ZAPISZ W BAZIE
                                        </button>
                                    </form>
                                </div>

                                <!-- Kalkulator na żywo (TERMINAL STYLE) -->
                                <div class="lg:col-span-5 sticky top-24">
                                    <div class="brutal-card bg-black text-white p-0 overflow-hidden shadow-[8px_8px_0px_#facc15]">
                                        <div class="bg-yellow-400 text-black font-black uppercase p-3 border-b-[3px] border-black text-xl flex justify-between">
                                            <span>LIVE CALC</span>
                                            <span class="text-sm border-2 border-black px-1 bg-white">VAT: {{settings.vat_rate}}% | PIT: {{settings.income_tax_rate}}%</span>
                                        </div>
                                        
                                        <div class="p-6 font-mono text-lg space-y-4">
                                            
                                            <div class="border-b-2 border-dashed border-gray-700 pb-4">
                                                <div class="flex justify-between"><span>Dochód:</span> <span class="text-white">{{ formatCurrency(liveCalc.income) }}</span></div>
                                                <div class="flex justify-between mt-2"><span>Podatek (PIT):</span> <span class="text-rose-400">-{{ formatCurrency(liveCalc.income_tax) }}</span></div>
                                            </div>
                                            
                                            <div class="border-b-2 border-dashed border-gray-700 pb-4">
                                                <div class="flex justify-between"><span>VAT (od klienta):</span> <span class="text-cyan-400">{{ formatCurrency(liveCalc.vat_należny) }}</span></div>
                                                <div class="flex justify-between mt-2"><span>VAT (z kosztów):</span> <span class="text-lime-400">-{{ formatCurrency(liveCalc.vat_naliczony) }}</span></div>
                                                
                                                <div class="mt-4 p-2 font-black text-center text-xl" :class="liveCalc.vat_to_pay >= 0 ? 'bg-rose-500 text-black' : 'bg-cyan-500 text-black'">
                                                    {{ liveCalc.vat_to_pay >= 0 ? 'VAT DO US:' : 'VAT ZWROT:' }} {{ formatCurrency(Math.abs(liveCalc.vat_to_pay)) }}
                                                </div>
                                            </div>
                                            
                                        </div>
                                        
                                        <!-- Wynik na rękę -->
                                        <div class="bg-lime-400 p-6 border-t-[3px] border-black">
                                            <p class="font-black text-black uppercase text-xl mb-1">ZYSK NA CZYSTO:</p>
                                            <p class="text-5xl font-black text-black bg-white inline-block px-3 py-1 border-[4px] border-black shadow-[4px_4px_0px_#000]">{{ formatCurrency(liveCalc.net_profit) }}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- TAB: ADMINISTRACJA -->
                        <div v-else-if="currentTab === 'admin'" class="max-w-3xl mx-auto space-y-6">
                            <div>
                                <h1 class="text-4xl md:text-5xl font-black uppercase tracking-tighter drop-shadow-[2px_2px_0px_#000] text-white">USTAWIENIA</h1>
                            </div>
                            
                            <div class="brutal-card p-8 bg-white">
                                <form @submit.prevent="saveSettings" class="space-y-6">
                                    
                                    <div class="bg-[#c4a1ff] p-6 border-[3px] border-black">
                                        <h3 class="font-black text-2xl uppercase mb-6 bg-black text-white inline-block px-2">PODATKI & VAT</h3>
                                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            <div>
                                                <label class="block font-black uppercase mb-1">Stawka VAT (%)</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.vat_rate" required class="brutal-input w-full pr-8 text-xl">
                                                    <span class="absolute right-4 top-1/2 -translate-y-1/2 font-black text-xl">%</span>
                                                </div>
                                            </div>
                                            <div>
                                                <label class="block font-black uppercase mb-1">Podatek Dochodowy (%)</label>
                                                <div class="relative">
                                                    <input type="number" step="0.1" v-model="settings.income_tax_rate" required class="brutal-input w-full pr-8 text-xl">
                                                    <span class="absolute right-4 top-1/2 -translate-y-1/2 font-black text-xl">%</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="brutal-btn w-full py-4 text-xl bg-yellow-400">ZAPISZ SYSTEM</button>
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
                            this.showToast("ZAPISANO USTAWIENIA!");
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async saveInvoice() {
                        try {
                            const payload = {...this.form};
                            // Walidacja czy liczby nie są puste
                            payload.revenue_net = Number(payload.revenue_net) || 0;
                            payload.cost_net = Number(payload.cost_net) || 0;
                            payload.cost_gross = Number(payload.cost_gross) || 0;

                            await this.api('invoices', 'POST', payload);
                            this.showToast("DODANO DO BAZY!");
                            this.form = {
                                invoice_number: '', issue_date: new Date().toISOString().split('T')[0],
                                client_name: '', description: '', revenue_net: '', cost_net: '', cost_gross: ''
                            };
                            this.setTab('dashboard');
                        } catch(e) { this.showToast(e.message, 'error'); }
                    },
                    async deleteInvoice(id) {
                        if(!confirm("WYWALIĆ FAKTURĘ Z BAZY? TEGO NIE DA SIĘ COFNĄĆ!")) return;
                        try {
                            await this.api(`invoices/${id}`, 'DELETE');
                            this.invoices = this.invoices.filter(i => i.id !== id);
                            this.showToast("USUNIĘTO FAKTURĘ.");
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
