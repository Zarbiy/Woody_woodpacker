# 🪵 Woody Woodpacker - 42 Project

Projet de l’école **42** : écrire un packer en C qui chiffre un exécutable ELF64, et ajoute un *loader* pour le déchiffrer et exécuter le programme original.  

---

## 📖 Description

L’objectif du projet est de :
- Recompiler un binaire ELF64 en l’encapsulant avec un *packer*  
- Ajouter une couche de chiffrement
- Insérer un *loader* qui déchiffre et lance le programme original  
- Générer un nouvel exécutable appelé **woody**  

C’est une introduction à la **reverse engineering**, la **cryptographie simple** et au format **ELF64**.  

---

## 🛠️ Compilation

```bash
make
