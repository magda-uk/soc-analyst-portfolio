import os
import csv
import random
import string
from datetime import datetime, timedelta

# Configuración del entorno
TARGET_DIR = r"C:\Logistics_Data"
NUM_FILES = 30

def setup_directory(directory_path):
    """Crea el directorio objetivo si no existe, simulando la preparación del pipeline de datos."""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"[+] Directorio crítico creado: {directory_path}")

def generate_sku():
    """Genera un código SKU alfanumérico aleatorio estándar en logística."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def generate_pi_report(filepath):
    """Genera un archivo CSV simulando una reconciliación de Perpetual Inventory."""
    headers = ['Timestamp', 'SKU', 'System_Qty', 'Physical_Qty', 'Variance', 'Location_Zone']
    zones = ['Chilled_A', 'Chilled_B', 'Ambient_C', 'Frozen_D']
    
    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        for _ in range(random.randint(50, 150)):
            sys_qty = random.randint(10, 500)
            phys_qty = sys_qty + random.randint(-5, 5) # Simula pequeñas discrepancias
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                generate_sku(),
                sys_qty,
                phys_qty,
                phys_qty - sys_qty,
                random.choice(zones)
            ])

def generate_gfr_intake(filepath):
    """Genera un archivo CSV simulando registros de entrada GFR (Good Faith Receiving)."""
    headers = ['Date', 'Supplier_ID', 'Pallet_Count', 'Status', 'QA_Check']
    statuses = ['Cleared', 'Pending', 'Quarantine']
    
    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        for _ in range(random.randint(20, 80)):
            writer.writerow([
                (datetime.now() - timedelta(days=random.randint(0,30))).strftime("%Y-%m-%d"),
                f"SUP-{random.randint(1000, 9999)}",
                random.randint(1, 33),
                random.choice(statuses),
                random.choice(['Pass', 'Fail', 'N/A'])
            ])

def main():
    setup_directory(TARGET_DIR)
    print(f"[*] Generando {NUM_FILES} archivos de datos operativos...")
    
    for i in range(NUM_FILES):
        file_type = random.choice(['PI_Reconciliation', 'GFR_Intake'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{file_type}_{timestamp}_{i:03d}.csv"
        filepath = os.path.join(TARGET_DIR, filename)
        
        if file_type == 'PI_Reconciliation':
            generate_pi_report(filepath)
        else:
            generate_gfr_intake(filepath)
            
    print(f"[+] Generación completada. Datos vulnerables listos en {TARGET_DIR}")

if __name__ == "__main__":
    main()