# dr_source/core/usage.py
import javalang
import re
import logging

logger = logging.getLogger(__name__)


def find_usage_in_file(file_obj, target_class):
    """
    Parses the Java file (using javalang) and returns a tuple (used, current_class)
    where:
      - used: True if the target_class is used in the file (excluding its own declaration).
      - current_class: the name of the primary class declared in the file.
    """
    try:
        tree = javalang.parse.parse(file_obj.content)
    except Exception as e:
        logger.error("Error parsing %s: %s", file_obj.path, e)
        return False, None

    # Otteniamo il nome della classe dichiarata in questo file
    class_names = [
        node.name for path, node in tree.filter(javalang.tree.ClassDeclaration)
    ]
    current_class = class_names[0] if class_names else None

    # Cerchiamo nel file riferimenti al target_class.
    # Usiamo sia una semplice ricerca regex che l'analisi dell'AST.
    used = False

    # Controllo semplice su contenuto (parola intera)
    pattern = re.compile(r"\b" + re.escape(target_class) + r"\b")
    if pattern.search(file_obj.content):
        used = True

    # Ulteriore controllo tramite AST: per ogni ReferenceType o MemberReference,
    # se il nome corrisponde e non si tratta della dichiarazione della classe stessa, segna come usato.
    for path, node in tree:
        if isinstance(node, javalang.tree.ReferenceType) and hasattr(node, "name"):
            if node.name == target_class:
                used = True
                break
        if (
            isinstance(node, javalang.tree.MemberReference)
            and node.member == target_class
        ):
            used = True
            break

    return used, current_class


def where_is_it_used(codebase, target_class):
    """
    Itera su tutti i file Java del codebase. Per ogni file in cui la classe target è usata
    (e il nome della classe dichiarata è diverso da target_class), aggiunge un record.
    Restituisce una lista di dizionari:
      [{"class": <class_name>, "file": <file_path>}, ...]
    """
    usage_list = []
    for file_obj in codebase.files:
        # Processa solo file Java
        if not file_obj.path.endswith(".java"):
            continue
        used, current_class = find_usage_in_file(file_obj, target_class)
        # Se il target viene usato e il file non è la sua dichiarazione principale
        if used and current_class and current_class != target_class:
            usage_list.append({"class": current_class, "file": file_obj.path})
    return usage_list
