def normalize_label(label):
    # BUG (synthetic): does not trim surrounding whitespace.
    return label.lower()
