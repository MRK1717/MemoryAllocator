
---

### MemoryAllocator

```markdown
# MemoryAllocator

## Prezentare generală
MemoryAllocator este o bibliotecă de alocare a memoriei dezvoltată în C ca proiect de facultate.
Proiectul implementează funcții similare cu `malloc`, `free` și `realloc`,
cu scopul de a explora tehnicile de gestionare a memoriei și fragmentarea acesteia.

## Funcționalități
- Implementarea funcțiilor `malloc`, `free` și `realloc`
- Monitorizarea și gestionarea fragmentării memoriei
- Funcționalități de debugging și logare a operațiilor de alocare

## Cerințe
- Compilator C (de ex. GCC)
- Sistem de operare compatibil POSIX

## Compilare
Compilează proiectul și programul de test folosind:
```bash
gcc -o memory_allocator main.c allocator.c
