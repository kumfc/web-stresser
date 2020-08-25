import secrets
import socket
import time

import googleapiclient.discovery as gapid
from google.oauth2 import service_account


class GoogleComputeAPI:
    def __init__(self, path, project):
        # default machine name length, make sure this has enough entropy, cause we aren't checking if such name already exists
        self._bytes = 16
        # set longer timeout
        socket.setdefaulttimeout(300)

        self._project = project
        self._error = ''
        self._ready = False
        self._template = None
        self._templateMachineProperties = None
        self._account = None
        self._compute = None

        # not able to change zone currently, but whatever, do this for easier changing later
        self._zone = 'us-central1-a'

        try:
            self._account = service_account.Credentials.from_service_account_file(path)
            self._compute = gapid.build('compute', 'v1', credentials=self._account)
        except:
            self._error = 'Invalid key file supplied, can\'t create service account'
            return

        try:
            if self._compute.projects().get(project=project).execute()['name'] != project:
                self._error = 'Something wrong with key or project, try to check it'
        except:
            self._error = 'No permission for specified project "%s", specify new project or key' % (project,)

        if self._error:
            return

        try:
            templates = self._compute.instanceTemplates().list(project=project).execute()['items']
            for i in templates:
                if i['name'] == 'main-template':
                    self._template = i
                    break
            # didn't find main-template, can't create machines
            if not self._template:
                self._error = 'No template \"main-template\", won\'t be able to create machines. Please create a template on gcloud.'
        except:
            self._error = 'Can\'t get templates, something must be wrong with the key'

        if self._error:
            return

        try:
            self._templateMachineProperties = self._template['properties']
        except:
            self._error = 'Can\'t get the actual machine template, invalid template received. Try to check gcloud.'

        if self._error:
            return

        self.create_machine()
        if self._error:
            return

    def get_error(self):
        ret = self._error
        self._error = ''
        return ret

    def create_machine(self):
        if not self._template:
            self._error = 'Can\'t create machine - no template in class, previous error - "%s"' % (self._error,)
            return False, self._error
        if not self._templateMachineProperties:
            self._error = 'Can\'t create machine - no actual machine properties in class, previous error - "%s"' % (
            self._error,)
            return False, self._error

        properties = self._templateMachineProperties

        machineid = secrets.token_hex(self._bytes)
        machine_zone = "projects/%s/zones/%s" % (self._project, self._zone)
        machine_type = machine_zone + "/machineTypes/%s" % (properties['machineType'],)
        disk_type = machine_zone + "/diskTypes/%s" % (properties['disks'][0]['initializeParams']['diskType'],)

        properties['name'] = 'machine-%s' % (machineid,)
        properties['zone'] = machine_zone
        properties['machineType'] = machine_type
        properties['disks'][0]['deviceName'] = 'disk-%s' % (machineid,)
        properties['disks'][0]['initializeParams']['diskType'] = disk_type

        try:
            op = self._compute.instances().insert(project=self._project, zone=self._zone, body=properties).execute()
        except Exception as e:
            self._error = 'Can\'t create instance, error during insert: "%s"' % (str(e),)

        if self._error:
            return False, self._error

        try:
            wait_for_operation(self._compute, self._project, self._zone, op['name'])
        except Exception as e:
            self._error = 'Unable to wait for machine creation, error: "%s"' % (str(e),)

        if self._error:
            return False, self._error

        testInstance = None
        try:
            testInstance = self._compute.instances().get(project=self._project, zone=self._zone,
                                                         instance=properties['name']).execute()
        except Exception as e:
            self._error = 'Unable to get created instance, error: "%s"' % (str(e),)

        if testInstance['name'] != properties['name']:
            self._error = 'Something really bad happened with creating an instance, name (%s) is different from the one specified during creation (%s)' % (
            testInstance['name'], properties['name'])

        if self._error:
            return False, self._error

        return True, ''

    def check_ready(self):
        try:
            if self._compute.projects().get(project=project).execute()['name'] != project:
                return False, 'Something wrong with key or project, try to check it'
        except Exception as e:
            return False, 'No permission for specified project "%s", specify new project or key'


def wait_for_operation(compute, project, zone, operation):
    while True:
        result = compute.zoneOperations().get(
            project=project,
            zone=zone,
            operation=operation).execute()

        if result['status'] == 'DONE':
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(1)


def main():
    c = GoogleComputeAPI('main-api-key.json', 'secret-imprint-279817')
    print(c.get_error())


if __name__ == '__main__':
    main()
