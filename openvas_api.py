# requirement
# gvm-tools
import gvm
import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
import datetime
import json

scan_config_id = {
    # for more information click here: https://docs.greenbone.net/GSM-Manual/gos-3.1/en/scanning.html
    'Discovery': '8715c877-47a0-438d-98a3-27c7a6ab2196',
    'Host Discovery': '2d3f051c-55ba-11e3-bf43-406186ea4fc5',
    'System Discovery': 'bbca7412-a950-11e3-9109-406186ea4fc5',
    'Full and Fast': 'daba56c8-73ec-11df-a475-002264764cea',
    'Full and fast ultimate': '698f691e-7489-11df-9d8c-002264764cea',
    'Full and very deep': '708f25c4-7489-11df-8094-002264764cea',
    'Full and very deep ultimate': '74db13d6-7489-11df-91b9-002264764cea',
    'scanner_id': '08b69003-5fc2-4037-a479-93b440211c73',
}

report_format_id = {
    'html': '6c248850-1f62-11e1-b082-406186ea4fc5',
    'pdf': 'c402cc3e-b531-11e1-9163-406186ea4fc5',
    'xml': '5057e5cc-b825-11e4-9d0e-28d24461215b',
}


class gvm_api:
    def __init__(self, gvmuser, gvmpass, host='127.0.0.1', ):
        self._gvmuser = gvmuser
        self._gvmpass = gvmpass
        self._host = host

    def connect(self):

        connection = gvm.connections.TLSConnection(hostname=self._host)
        self._gmp = Gmp(connection=connection)
        self._gmp.authenticate(username=self._gvmuser, password=self._gvmpass)
        self._gmp.connect()
        return 'connect successfully';

    def report(self, report_id, report_format):
        response = self._gmp.get_report(
            report_id=report_id, report_format_id=report_format_id.get(report_format)
        )
        dict_xml = xmltodict.parse(response)
        print(response)
        return dict_xml['get_reports_response']['report']['#text']

    def get_scan_config(self):
        response = self._gmp.get_configs()
        jsonconf = json.loads(json.dumps(xmltodict.parse(response)))
        out = []
        for i in range(len(jsonconf['get_configs_response']['config']) - 1):
            out.append(json.dumps({
                "name": jsonconf['get_configs_response']['config'][i]['name'],
                "comment": jsonconf['get_configs_response']['config'][i]['comment'],
                "id": jsonconf['get_configs_response']['config'][i]['@id']
            }))
        return out

    def newscan(self, target, scanconfig, ssh_credential=None, snmp_credential=None, smb_credential=None,
                esxi_credential=None):
        # for more information about scan config click here: https://docs.greenbone.net/GSM-Manual/gos-3.1/en/scanning.html
        # up credential id ==ssh,smb,esxi
        # usd credential id == ssh
        # snmp credential ==ssh
        target_id = self._create_target(target=target,
                                        ssh_credential=ssh_credential,
                                        snmp_credential=snmp_credential,
                                        smb_credential=smb_credential,
                                        esxi_credential=esxi_credential,
                                        )
        task_id = self._create_task(target, target_id, scanconfig, scan_config_id.get('scanner_id'))
        report_id = self._start_task(task_id)
        return task_id + '\n' + report_id

    def removeData(self):
        tasks = self._gmp.get_tasks(
            filter="rows=-1 not status=Running and "
                   "not status=Requested and not "
                   "status=&quot;Stop Requested&quot;")
        tasks_dict = xmltodict.parse(tasks)
        if tasks_dict['get_tasks_response']['task_count']['#text'] != '1':
            for taid in range(int(tasks_dict['get_tasks_response']['task_count']['#text'])):
                print(self._gmp.delete_task(tasks_dict['get_tasks_response']['task'][taid]['@id']))
        else:
            print(self._gmp.delete_task(tasks_dict['get_tasks_response']['task']['@id']))
        targets = self._gmp.get_targets(filter="rows=-1 not _owner=&quot;&quot;")
        target_dict = xmltodict.parse(targets)
        if target_dict['get_targets_response']['target_count']['#text'] != '1':
            for taid in range(int(target_dict['get_targets_response']['target_count']['#text'])):
                print(self._gmp.delete_target(target_dict['get_targets_response']['target'][taid]['@id']))
        else:
            print(self._gmp.delete_target(target_dict['get_targets_response']['target']['@id']))

        credentials = self._gmp.get_credentials(filter="rows=-1 not _owner=&quot;&quot;")
        credentials_dict = xmltodict.parse(credentials)
        if credentials_dict['get_credentials_response']['credential_count']['#text'] != '1':
            for cid in range(int(credentials_dict['get_credentials_response']['credential_count']['#text'])):
                print(
                    self._gmp.delete_credential(credentials_dict['get_credentials_response']['credential'][cid]['@id']))
        else:
            print(self._gmp.delete_credential(credentials_dict['get_credentials_response']['credential']['@id']))
        status_text = self._gmp.empty_trashcan()
        return 'Done'

    def task_status(self, task_id):
        respose = self._gmp.get_task(task_id)
        tasks_dict = xmltodict.parse(respose)
        return tasks_dict['get_tasks_response']['task']['status']  # Running,Done,Stop Requested

    def create_up_credential(self, name, username, password):
        # create user name + password credential
        response = self._gmp.create_credential(credential_type='up',
                                               name=name,
                                               login=username,
                                               password=password)
        id_xml = xmltodict.parse(response)
        if id_xml['create_credential_response']['@status_text'] == 'Credential exists already':
            return 'Credential exists already'
        else:
            return id_xml['create_credential_response']['@id']

    def create_usk_credential(self, name, username, passphrase, private_key):
        # create username + ssh key ,The private key should read the file and send the string
        response = self._gmp.create_credential(
            credential_type='usk',
            name=name,
            login=username,
            key_phrase=passphrase,
            private_key=private_key,
        )

        id_xml = xmltodict.parse(response)
        status_text = id_xml['create_credential_response']['@status_text']
        if status_text == 'Credential exists already':
            return 'Credential exists already'
        elif status_text == 'Erroneous private key or associated passphrase':
            return 'private key is not valid'
        else:
            return id_xml['create_credential_response']['@id']

    def create_cc_credential(self, name, certificate, private_key):
        # Client Certificates ,The private key and certificate should read the file and send the string
        response = self._gmp.create_credential(
            credential_type='cc',
            name=name,
            certificate=certificate,
            private_key=private_key,
        )
        id_xml = xmltodict.parse(response)
        status_text = id_xml['create_credential_response']['@status_text']
        if status_text == 'Credential exists already':
            return 'Credential exists already'
        elif status_text == 'Erroneous private key or associated passphrase':
            return 'private key is not valid'
        else:
            return id_xml['create_credential_response']['@id']

    def create_snmp_credential(self, name, community, auth_algorithm, username=None, paseeword=None,
                               privacy_algorithm=None, privacy_password=None):
        # auth_algorithm ='md5' or 'sha1'
        # privacy_algorithm  aes or des or none
        response = self._gmp.create_credential(
            credential_type='snmp',
            name=name,
            login=username,
            password=paseeword,
            community=community,
            auth_algorithm=auth_algorithm,
            privacy_algorithm=privacy_algorithm,
            privacy_password=privacy_password

        )
        id_xml = xmltodict.parse(response)
        if id_xml['create_credential_response']['@status_text'] == 'Credential exists already':
            return 'Credential exists already'
        else:
            return id_xml['create_credential_response']['@id']

    def _create_target(self, target, ssh_credential, snmp_credential, smb_credential, esxi_credential):
        # create a unique name by adding the current datetime
        name = "Suspect Host {} {}".format(target, str(datetime.datetime.now()))
        response = self._gmp.create_target(name=name,
                                           hosts=[target],
                                           # ssh_port=ssh_port,
                                           ssh_credential_id=ssh_credential,
                                           snmp_credential_id=snmp_credential,
                                           smb_credential_id=smb_credential,
                                           esxi_credential_id=esxi_credential)
        id_xml = xmltodict.parse(response)
        return id_xml['create_target_response']['@id']

    def _create_task(self, target, target_id, scan_config_id, scanner_id):
        name = "Scan Suspect Host {}".format(target)
        response = self._gmp.create_task(
            name=name,
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        task_id_xml = xmltodict.parse(response)
        task_id = task_id_xml['create_task_response']['@id']
        return task_id

    def _start_task(self, task_id):
        response = self._gmp.start_task(task_id)
        dict_response = xmltodict.parse(response)
        return dict_response['start_task_response']['report_id']
