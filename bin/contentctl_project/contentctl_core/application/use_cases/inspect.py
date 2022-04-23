class Inspect:
    def __init__(self, args):
        try:
            import magic
        except Exception as e:
            print("Failed to import libmagic.  If you're on macOS, you probably need to run 'brew install libmagic'")
            raise(Exception(f"AppInspect Failed to import magic: str(e)"))
        import splunk_appinspect
