from app.interactors.google_api import GoogleComputeAPI

# PIDORAS DEFAULT
# main-api-key.json secret-imprint-279817


class Globals:
    def __init__(self):
        self.google_api = None
        self.db = None

    def set_apikey(self, key_file, project_name):
        key_path = f'./secrets/{key_file}'
        c = GoogleComputeAPI(key_path, project_name)

        err = c.get_error()
        if len(err):
            print(f'Cannot initialize Google Cloud API: {err}')
            return False
        else:
            self.google_api = c
            return True
