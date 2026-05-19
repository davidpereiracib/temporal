#!/usr/bin/env python3
import os, sys, email, hashlib
from email import policy
from pathlib import Path

if len(sys.argv) != 3:
    print("Uso: python3 extraer_v2.py <dir_entrada> <dir_salida>")
    sys.exit(1)

entrada = Path(sys.argv[1])
salida = Path(sys.argv[2])
salida.mkdir(parents=True, exist_ok=True)

eml_files = list(entrada.rglob("*.eml"))
print(f"Archivos .eml encontrados: {len(eml_files)}")

if len(eml_files) == 0:
    print("No se encontraron archivos .eml. Abortando.")
    sys.exit(1)

adjuntos_total = 0
con_adjuntos = 0

for i, archivo in enumerate(eml_files, 1):
    if i % 500 == 0 or i == len(eml_files):
        print(f"  Procesados {i}/{len(eml_files)} | adjuntos: {adjuntos_total}")
    try:
        with open(archivo, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        encontrados_aqui = 0
        for parte in msg.walk():
            if parte.get_content_maintype() == 'multipart':
                continue
            payload = parte.get_payload(decode=True)
            if not payload:
                continue
            nombre = parte.get_filename()
            disp = parte.get('Content-Disposition', '') or ''
            ctype = parte.get_content_type()
            # Considerar adjunto si tiene filename, disposition=attachment, o no es texto
            es_adjunto = bool(nombre) or 'attachment' in disp.lower() or not ctype.startswith('text/')
            if not es_adjunto:
                continue
            if not nombre:
                ext = parte.get_content_subtype() or 'bin'
                nombre = f"adj_{hashlib.md5(payload).hexdigest()[:8]}.{ext}"
            sub = salida / archivo.stem
            sub.mkdir(parents=True, exist_ok=True)
            destino = sub / nombre
            n = 1
            while destino.exists():
                destino = sub / f"{destino.stem}_{n}{destino.suffix}"
                n += 1
            destino.write_bytes(payload)
            adjuntos_total += 1
            encontrados_aqui += 1
        if encontrados_aqui > 0:
            con_adjuntos += 1
    except Exception as e:
        print(f"  ✗ Error en {archivo.name}: {e}")

print(f"\n=== Resumen ===")
print(f"Correos procesados: {len(eml_files)}")
print(f"Correos con adjuntos: {con_adjuntos}")
print(f"Adjuntos extraídos: {adjuntos_total}")
print(f"Salida: {salida}")
