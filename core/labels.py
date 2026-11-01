"""Public wording; persisted category/rule identifiers remain API-compatible."""
CATEGORY_DISPLAY={
    'Earned the hype':'High attention + observed exploitation',
    'Overhyped':'High attention + lower observed evidence',
    'Sleeper':'Observed exploitation + lower recent attention',
    'Watch':'Public PoC / high prediction',
    'Quiet':'Below category thresholds',
    'Unknown':'Insufficient fresh data',
}


def category_display(key):
    return CATEGORY_DISPLAY.get(key,key or 'Uncategorized')
