from pathlib import Path
from pypdf import PdfReader

def extraer_texto_pdf(ruta_pdf):
    reader = PdfReader(ruta_pdf)
    texto = ""
    for pagina in reader.pages:
        texto += pagina.extract_text() or ""
    return texto

if __name__ == "__main__":
    carpeta = Path("docs")
    carpeta.mkdir(exist_ok=True)

    pdfs = list(carpeta.glob("*.pdf"))

    if not pdfs:
        print("Mete un PDF dentro de la carpeta docs y vuelve a ejecutar")
    else:
        texto = extraer_texto_pdf(pdfs[0])
        Path("salida.txt").write_text(texto, encoding="utf-8")
        print("PDF leído correctamente. Texto guardado en salida.txt")
