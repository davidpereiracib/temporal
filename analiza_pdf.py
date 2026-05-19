#!/usr/bin/env python3
"""
Detecta PDFs sospechosos dentro de un directorio:
- Verifica que sean PDFs reales (magic bytes %PDF-)
- Busca elementos peligrosos: /JS, /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile
- Calcula hash SHA-256 para cadena de custodia
- Genera un reporte CSV
"""
import os, sys, hashlib, re, csv
from pathlib import Path

if len(sys.argv) < 2:
    print("Uso: python3 detectar_pdf_malicioso.py <dir_adjuntos> [reporte.csv]")
    sys.exit(1)

dir_adj = Path(sys.argv[1])
reporte = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("reporte_pdfs_sospechosos.csv")

# Marcadores peligrosos en orden de severidad
MARCADORES = [
    b'/JavaScript', b'/JS', b'/OpenAction', b'/AA',
    b'/Launch', b'/EmbeddedFile', b'/RichMedia', b'/URI'
]

CRITICOS = {b'/JavaScript', b'/JS', b'/OpenAction', b'/Launch', b'/AA'}

def es_pdf(ruta):
    """Verifica magic bytes."""
    try:
        with open(ruta, 'rb') as f:
            return f.read(5) == b'%PDF-'
    except:
        return False

def analizar_pdf(ruta):
    """Cuenta marcadores sospechosos en el PDF."""
    try:
        with open(ruta, 'rb') as f:
            contenido = f.read()
    except:
        return None
    hallazgos = {}
    for marcador in MARCADORES:
        # Contar ocurrencias del marcador seguido de espacio, /, < o salto
        patron = re.compile(re.escape(marcador) + rb'[\s/<\[\(]')
        n = len(patron.findall(contenido))
        if n > 0:
            hallazgos[marcador.decode()] = n
    return hallazgos

def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

print(f"Buscando PDFs en: {dir_adj}")
todos = list(dir_adj.rglob("*"))
candidatos = [f for f in todos if f.is_file()]
print(f"Archivos totales: {len(candidatos)}")

pdfs = []
for i, f in enumerate(candidatos, 1):
    if i % 1000 == 0:
        print(f"  Verificando {i}/{len(candidatos)}...")
    if es_pdf(f):
        pdfs.append(f)

print(f"PDFs reales encontrados: {len(pdfs)}\n")

sospechosos = []
for i, pdf in enumerate(pdfs, 1):
    if i % 100 == 0:
        print(f"  Analizando {i}/{len(pdfs)}...")
    hallazgos = analizar_pdf(pdf)
    if not hallazgos:
        continue
    tiene_critico = any(m in hallazgos for m in [c.decode() for c in CRITICOS])
    if tiene_critico or len(hallazgos) >= 3:
        sospechosos.append({
            'archivo': str(pdf),
            'tamano': pdf.stat().st_size,
            'sha256': sha256(pdf),
            'hallazgos': hallazgos,
            'critico': tiene_critico
        })

# Ordenar por criticidad
sospechosos.sort(key=lambda x: (not x['critico'], -len(x['hallazgos'])))

print(f"\n{'='*60}")
print(f"RESUMEN: {len(sospechosos)} PDFs sospechosos de {len(pdfs)} totales")
print(f"{'='*60}\n")

for s in sospechosos[:20]:  # mostrar los 20 primeros en pantalla
    nivel = "🚨 CRITICO" if s['critico'] else "⚠️  SOSPECHOSO"
    print(f"{nivel}: {s['archivo']}")
    print(f"  SHA-256: {s['sha256']}")
    print(f"  Tamaño:  {s['tamano']} bytes")
    print(f"  Hallazgos: {s['hallazgos']}")
    print()

if len(sospechosos) > 20:
    print(f"... y {len(sospechosos) - 20} más en el reporte CSV.\n")

# Guardar CSV completo
with open(reporte, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['nivel', 'archivo', 'tamano_bytes', 'sha256',
                'JavaScript', 'JS', 'OpenAction', 'AA', 'Launch',
                'EmbeddedFile', 'RichMedia', 'URI', 'total_marcadores'])
    for s in sospechosos:
        h = s['hallazgos']
        w.writerow([
            'CRITICO' if s['critico'] else 'SOSPECHOSO',
            s['archivo'], s['tamano'], s['sha256'],
            h.get('/JavaScript', 0), h.get('/JS', 0),
            h.get('/OpenAction', 0), h.get('/AA', 0),
            h.get('/Launch', 0), h.get('/EmbeddedFile', 0),
            h.get('/RichMedia', 0), h.get('/URI', 0),
            sum(h.values())
        ])

print(f"✓ Reporte completo guardado en: {reporte.absolute()}")
