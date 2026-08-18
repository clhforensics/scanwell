def update_yara_rules(self, new_rules_path):
    """
    Update or add new YARA rules
    """
    try:
        # Validate new rules first
        test_compile = yara.compile(new_rules_path)
        # If compilation successful, update rules
        self.rules = test_compile
        return True
    except Exception as e:
        logging.error(f"Error updating YARA rules: {e}")
        return False