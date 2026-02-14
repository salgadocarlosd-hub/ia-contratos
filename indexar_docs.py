from sentence_transformers import SentenceTransformer
import faiss
from pathlib import Path

modelo = SentenceTransformer("all-MiniLM-L6-v2")

docs = []
rutas = []

carpeta = Path("docs")

for archivo in carpeta.glob("*.txt"):
    texto = archivo.read_text(encoding="utf-8")
    docs.append(texto)
    rutas.append(str(archivo))

embeddings = modelo.encode(docs)

index = faiss.IndexFlatL2(embeddings.shape[1])
index.add(embeddings)

faiss.write_index(index, "indice.faiss")

with open("rutas.txt", "w", encoding="utf-8") as f:
    for r in rutas:
        f.write(r + "\n")

print("Indexado terminado")
