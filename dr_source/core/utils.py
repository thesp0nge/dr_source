from typing import Dict, Any, List


def deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merges a 'source' dictionary (high priority) into a 'target' dictionary (low priority).

    This is a cascading configuration merge: the SOURCE always wins
    over the TARGET (lower priority) for scalar values.
    """

    # Iterate over the higher-priority source dictionary
    for key, source_value in source.items():
        target_value = target.get(key)

        # 1. If both are dictionaries, recurse
        if (
            key in target
            and isinstance(target_value, dict)
            and isinstance(source_value, dict)
        ):
            target[key] = deep_merge(target_value, source_value)

        # 2. If the key exists and both are lists, extend the list
        elif (
            key in target
            and isinstance(target_value, list)
            and isinstance(source_value, list)
        ):
            # --- CRITICAL FIX ---
            # Ensure target is extended by source, maintaining target's original order.
            target_value.extend(source_value)
            # --- END CRITICAL FIX ---

        # 3. Otherwise (scalar value, type mismatch, or new key), SOURCE WINS.
        else:
            target[key] = source_value

    return target
