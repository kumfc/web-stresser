from google.oauth2 import service_account
import googleapiclient.discovery as gapid
import secrets
import socket
import time
from requests import HTTPError

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

        # list of currently available machines
        self.machines = dict()

        # not able to change zone currently, but whatever, do this for easier changing later
        self._zone = 'us-central1-a'
        
        try:
            self._account = service_account.Credentials.from_service_account_file(path)
            self._compute = gapid.build('compute', 'v1', credentials=self._account)
        except:
            self._error = 'Invalid key file supplied, can\'t create service account'
            return

        try:
            self._startupscript = open('start.sh').read()
        except:
            self._error = 'Can\'t read startup script, won\'t be able to create attacking machines'
            return

        try:
            if self._compute.projects().get(project=project).execute()['name'] != project:
                self._error = 'Something wrong with key or project, try to check it'
        except HTTPError as err:
            if err.code == 403:
                self._error = 'No permission for specified project "%s", specify new project or key' % (project,)
            else:
                self._error = 'Something wrong with gcloud, can\'t get project, error: "%s"' % (str(err),)
        except Exception as e:
            self._error = 'Something wrong with gcloud, can\'t get project, error: "%s"' % (str(err),)
        
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

    def get_error(self):
        ret = self._error
        self._error = ''
        return ret

    def create_machine(self):
        self._error = ''

        if not self._template:
            self._error = 'Can\'t create machine - no template in class'
            return False, None
        if not self._templateMachineProperties:
            self._error = 'Can\'t create machine - no actual machine properties in class'
            return False, None

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
        if 'items' not in properties['metadata']:
            properties['metadata']['items'] = [{'key':'startup-script', 'value':self._startupscript}]
        else:
            properties['metadata']['items'].append({'key':'startup-script', 'value':self._startupscript})

        try:
            op = self._compute.instances().insert(project=self._project, zone=self._zone, body=properties).execute()
        except Exception as e:
            self._error = 'Can\'t create instance, error during insert: "%s"' % (str(e),)

        if self._error:
            return False, None

        try:
            wait_for_operation(self._compute, self._project, self._zone, op['name'])
        except Exception as e:
            self._error = 'Unable to wait for machine creation, error: "%s"' % (str(e),)

        if self._error:
            return False, None

        testInstance = None
        try:
            testInstance = self._compute.instances().get(project=self._project, zone=self._zone, instance=properties['name']).execute()
        except Exception as e:
            self._error = 'Unable to get created instance, error: "%s"' % (str(e),)

        if testInstance['name'] != properties['name']:
            self._error = 'Something really bad happened with creating an instance, name (%s) is different from the one specified during creation (%s)' % (testInstance['name'],properties['name'])
        
        if self._error:
            return False, None

        ip = ''
        try:
            ip = testInstance['networkInterfaces'][0]['accessConfigs'][0]['natIP']
        except:
            self._error = 'Machine created, but unable to get IP, probably instance template doesn\'t allow outside access, please check'
        
        if self._error:
            return False, None

        self.machines[properties['name']] = ip

        return True, (properties['name'], ip)

    def delete_machine(self, name):
        self._error = ''

        try:
            op = self._compute.instances().delete(project=self._project, zone=self._zone, instance=name).execute()
        except Exception as e:
            self._error = 'Can\'t delete instance "%s", error: "%s"' % (name, str(e))

        if self._error:
            return False

        try:
            wait_for_operation(self._compute, self._project, self._zone, op['name'])
        except HTTPError as err:
            if err.code == 400:
                self._error = 'Can\'t delete instance "%s" - no such instance was previously created. Try to check gcloud.'
            else:
                self._error = 'Unable to wait for machine deletion, error: "%s"' % (str(self._error),)
        except Exception as e:
           self._error =  'Unable to wait for machine deletion, error: "%s"' % (str(e),)
        
        if self._error:
            return False
        
        try:
            self.machines.pop(name)
        except:
            pass

        return True

    def check_ready(self):
        return self._ready

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
    res, name = c.create_machine()
    if not res:
        print(c.get_error())
    else:
        print('Created machine: %s with ip %s' % (name[0],name[1]))

if __name__ == '__main__':
    main()