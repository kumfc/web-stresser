from app.interactors.google_api import GoogleComputeAPI


class Globals:
    def __init__(self):
        self.google_api = None
        self.db = None

    def set_apikey(self, key):
        self.google_api = GoogleComputeAPI(key)
        return self.google_api.check_auth_key()
