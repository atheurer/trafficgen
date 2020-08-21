# Copyright 2016-2017 Red Hat Inc & Xena Networks.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Contributors:
#   Christian Trautman, Red Hat Inc.
#

import argparse
import json
import locale
import logging
import os
import subprocess
import sys
from time import sleep
import xml.etree.ElementTree as ET
import base64
#import pdb # debug

import pprint

pp = pprint.PrettyPrinter(indent=4)

_LOGGER = logging.getLogger(__name__)
_LOCALE = locale.getlocale()[1]
_XENA_USER = 'TestUser'
_PYTHON_2 = sys.version_info[0] < 3

_FLOWS = {
    '1': {
        'flows': 1,
        'stops': [0],
        'masks': ['//8='],
        'repeats': [1],
        'offsets': [2],
    },
    '1k': {
        'flows': 1000,
        'stops': [999],
        'masks': ['//8='],
        'repeats': [1],
        'offsets': [2]
    },
    '4k': {
        'flows': 4000,
        'stops': [3999],
        'masks': ['//8='],
        'repeats': [1],
        'offsets': [2]
    },
    '10k': {
        'flows': 10000,
        'stops': [9999],
        'masks': ['//8='],
        'repeats': [1],
        'offsets': [2]
    },
    '100k': {
        'flows': 100000,
        'stops': [999, 99],
        'masks': ['D/8=', '//A='],
        'repeats': [1, 1000],
        'offsets': [2, 1]
    },
    '1M': {
        'flows': 1000000,
        'stops': [999, 999],
        'masks': ['D/8=', '//A='],
        'repeats': [1, 1000],
        'offsets': [2, 1]
    }
}

class XenaJSON(object):
    """
    Class to modify and read Xena JSON configuration files.
    """
    def __init__(self, json_path):
        """
        Constructor
        :param json_path: path to JSON file to read. Expected files must have
         two module ports with each port having its own stream config profile.
        :return: XenaJSON object
        """
        self.json_data = read_json_file(json_path)
        self.min_tput = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['MinimumValue']
        self.init_tput = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['InitialValue']
        self.max_tput = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['MaximumValue']
        self.value_thresh = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['ValueResolution']
        self.duration = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['Duration']

        self.packet_sizes = self.json_data['TestOptions']['PacketSizes'][
            'CustomPacketSizes']
        self.accept_loss = self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['AcceptableLoss']
        self.active_ids = list(self.json_data['StreamProfileHandler'][
            'ProfileAssignmentMap'].values())  # Assume 1 <= len(active_ids) <=2
        self.entities = self.json_data['StreamProfileHandler']['EntityList']
        self.active_entities = [x for x in self.entities if x['ItemID'] in self.active_ids]
        self.filename = self.json_data['ReportConfig']['ReportFilename']

    # pylint: disable=too-many-arguments
    def modify_2544_tput_options(self, initial_value=None, value_resolution = None, 
                                 minimum_value=None, maximum_value=None):
        

        self.init_tput = initial_value = self.init_tput if initial_value == None else initial_value
        self.min_tput = minimum_value = self.min_tput if minimum_value == None else minimum_value
        self.max_tput = maximum_value = self.max_tput if maximum_value == None else maximum_value
        self.value_thresh = value_resolution = self.value_thresh if value_resolution == None else value_resolution
        """
        modify_2544_tput_options
        """
        self.json_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['InitialValue'] = initial_value
        self.json_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['MinimumValue'] = minimum_value
        self.json_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['MaximumValue'] = maximum_value
        

    def modify_module(self, module):
        """
        Modify module
        :param module: the module number to be used as int
        :return: None
        """
        for entity in self.json_data['PortHandler']['EntityList']:
            entity['PortRef']['ModuleIndex'] = module 

    def modify_duration(self, duration):
        """
        Modify test duration
        :param duration: test time duration in seconds as int
        :return: None
        """
        self.json_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Duration'] = duration

    def modify_latency(self):
        """
        Enable Latency in json file
        :return: None
        """
        self.json_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'ReportPropertyOptions'] = ['LatencyCounters']

    def modify_packet_size(self, packet_sizes):
        """
        Modify custom packet sizes
        :return: None
        """
        self.json_data['TestOptions']['PacketSizes']['CustomPacketSizes'] = packet_sizes

    def modify_acceptable_loss(self, acceptable_loss):
        """
        Modify acceptable loss
        :return: None
        """
        self.json_data['TestOptions']['TestTypeOptionMap'][
            'Throughput']['RateIterationOptions']['AcceptableLoss'] = acceptable_loss

    def modify_mac_address(self, new_mac_addresses):
        """
        Modify source and destination mac addresses
        :param mac_addresses: list of either one or two mac addresses
        :return: None
        """
        
        list_new_macs = [x.split(':') for x in new_mac_addresses]
        curr_macs = [list(base64.b64decode(x['StreamConfig']['HeaderSegments'][
                                           0]['SegmentValue'])) 
                    for x in self.active_entities]
        for i in range(0, 6):
            curr_macs[0][6 + i] = int(list_new_macs[0][i], 16)
            if len(curr_macs) == 2:
                curr_macs[1][i] = int(list_new_macs[0][i], 16)
        
        if len(list_new_macs) == 2:
            for i in range(0, 6):
                curr_ips[0][i] = int(list_new_macs[1][i], 16)
                if len(curr_macs) == 2:
                    curr_macs[1][6 + i] = int(list_new_macs[1][i], 16)
                    
        index_entities = 0
        index_macs = 0
        
        for entity in self.entities:
            if entity['ItemID'] in self.active_ids:
                self.json_data['StreamProfileHandler']['EntityList'][
                    index_entities]['StreamConfig']['HeaderSegments'][
                    0]['SegmentValue'] = base64.b64encode(bytes(curr_macs[index_macs])).decode('ascii')
                index_macs += 1
            
            index_entities += 1

    def modify_ip_address(self, new_ips):
        """
        Modify source and destination ip addresses
        :param ips: list of either one or two ip adresses
        :return: None
        """
        
        list_new_ips = [x.split('.') for x in new_ips]
        curr_ips = [list(base64.b64decode(x['StreamConfig']['HeaderSegments'][
                                           1]['SegmentValue'])) 
                    for x in self.active_entities]

        for i in range(0, 4):
            curr_ips[0][12 + i] = int(list_new_ips[0][i])
            if len(curr_ips) == 2:
                curr_ips[1][16 + i] = int(list_new_ips[0][i])
        
        if len(list_new_ips) == 2:
            for i in range(0, 4):
                curr_ips[0][16 + i] = int(list_new_ips[1][i])
                if len(curr_ips) == 2:
                    curr_ips[1][12 + i] = int(list_new_ips[1][i])
                    
        index_entities = 0
        index_ips = 0
        
        for entity in self.entities:
            if entity['ItemID'] in self.active_ids:
                self.json_data['StreamProfileHandler']['EntityList'][
                    index_entities]['StreamConfig']['HeaderSegments'][
                    1]['SegmentValue'] = base64.b64encode(bytes(curr_ips[index_ips])).decode('ascii')
                index_ips += 1
            
            index_entities += 1

    def modify_flows(self, flow_count, use_ip, use_mac):


        for i in range(len(self.json_data['StreamProfileHandler']['EntityList'])):
            self.json_data['StreamProfileHandler']['EntityList'][i][
                'StreamConfig']['HwModifiers'] = []
        
        if use_ip:
            self.modify_ip_flow(flow_count)
        if use_mac:
            self.modify_mac_flow(flow_count)

    def modify_ip_flow(self, flow_count):
        flow = _FLOWS[flow_count]

        field_names = ['Src IP Addr', 'Dest IP Addr']

        common = {
            'Action': 'INC',
            'StartValue': 0,
            'StepValue': 1
        }

        entity_index = 0

        for entity in self.entities:
            if entity['ItemID'] in self.active_ids:

                ip_id = entity['StreamConfig']['HeaderSegments'][
                        1]['ItemID']

                to_append = []

                for i in range(len(flow['stops'])):
                    for j in field_names:
                        to_append.append({
                            'Mask': flow['masks'][i],
                            'Action': common['Action'],
                            'Offset': flow['offsets'][i],
                            'StartValue': common['StartValue'],
                            'StepValue': common['StepValue'],
                            'StopValue': flow['stops'][i],
                            'RepeatCount': flow['repeats'][i],
                            'SegmentId': ip_id,
                            'FieldName': j
                        })
                self.json_data['StreamProfileHandler']['EntityList'][
                    entity_index]['StreamConfig']['HwModifiers'] += to_append
               
            entity_index += 1

        
    def modify_mac_flow(self, flow_count):
        flow = _FLOWS[flow_count]

        field_names = ['Src MAC addr', 'Dst MAC addr']

        common = {
            'Action': 'INC',
            'StartValue': 0,
            'StepValue': 1,
            'Mask': '//8='
        }

        entity_index = 0

        for entity in self.entities:
            if entity['ItemID'] in self.active_ids:

                mac_id = entity['StreamConfig']['HeaderSegments'][
                        0]['ItemID']

                to_append = []

                for i in range(len(flow['stops'])):
                    for j in field_names:
                        to_append.append({
                            'Mask': common['Mask'],
                            'Action': common['Action'],
                            'Offset': flow['offsets'][i]*2,
                            'StartValue': common['StartValue'],
                            'StepValue': common['StepValue'],
                            'StopValue': flow['stops'][i],
                            'RepeatCount': flow['repeats'][i],
                            'SegmentId': mac_id,
                            'FieldName': j
                        })
                self.json_data['StreamProfileHandler']['EntityList'][
                    entity_index]['StreamConfig']['HwModifiers'] += to_append

            entity_index += 1
        
        

    def modify_reporting(self, pdf_enable=True, csv_enable=False,
                         xml_enable=True, html_enable=False,
                         timestamp_enable=False, int_results=False):
        """
        Modify the reporting options
        :param pdf_enable: Enable pdf output, should disable for linux
        :param csv_enable: Enable csv output
        :param xml_enable: Enable xml output
        :param html_enable: Enable html output
        :param timestamp_enable: Enable timestamp to report
        :param int_results: Enable intermediate results
        :return: None
        """
        self.json_data['ReportConfig'][
            'GeneratePdf'] = 'true' if pdf_enable else 'false'
        self.json_data['ReportConfig'][
            'GenerateCsv'] = 'true' if csv_enable else 'false'
        self.json_data['ReportConfig'][
            'GenerateXml'] = 'true' if xml_enable else 'false'
        self.json_data['ReportConfig'][
            'GenerateHtml'] = 'true' if html_enable else 'false'
        self.json_data['ReportConfig'][
            'AppendTimestamp'] = 'true' if timestamp_enable else 'false'
        self.json_data['ReportConfig'][
            'SaveIntermediateResults'] = 'true' if int_results else 'false'

    def write_config(self, path='./2bUsed.x2544'):
        """
        Write the config to out as file
        :param path: Output file to export the json data to
        :return: None
        """
        if not write_json_file(self.json_data, path):
            raise RuntimeError("Could not write out file, please check config")


def main(args):
    _LOGGER.setLevel(logging.DEBUG if args.debug else logging.INFO)
    stream_logger = logging.StreamHandler(sys.stdout)
    stream_logger.setFormatter(logging.Formatter(
        '[%(levelname)-5s]  %(asctime)s : (%(name)s) - %(message)s'))
    _LOGGER.addHandler(stream_logger)
    # get the current json config into an object
    xena_current = XenaJSON(args.config_file)
    # Modify to output xml always as its needed to parse, turn off PDF output
    # unless user specifies it. Usually not supported on Linux. Also need to
    # disable the timestamp
    xena_current.modify_reporting(True if args.pdf_output else False,
                                  True, True, False, False, True)
    if args.search_trial_duration:
        xena_current.modify_duration(args.search_trial_duration)
    if args.collect_latency:
        xena_current.modify_latency()
    if args.packet_sizes:
        xena_current.modify_packet_size(args.packet_sizes)
    if args.acceptable_loss:
        xena_current.modify_acceptable_loss(args.acceptable_loss)
    if args.initial_tput:
        xena_current.modify_2544_tput_options(initial_value=args.initial_tput)
    if args.max_tput:
        xena_current.modify_2544_tput_options(maximum_value=args.max_tput)
    if args.min_tput:
        xena_current.modify_2544_tput_options(minimum_value=args.min_tput)
    if args.resolution_tput:
        xena_current.modify_2544_tput_options(value_resolution=args.resolution_tput)
    if args.mac_address:
        xena_current.modify_mac_address(args.mac_address)
    if args.connection_ips:
        xena_current.modify_ip_address(args.connection_ips)
    if args.flow_count:
        xena_current.modify_flows(args.flow_count, not args.use_mac_flows or args.use_both_flows, args.use_mac_flows or args.use_both_flows) 
    if args.module:
        print(args.module)

    xena_current.write_config(args.save_file_name)

    #pdb.set_trace()

    result = run_xena(args.save_file_name, args.windows_mode)

    # now run the verification step by creating a new config with the desired
    # params
    for _ in range(1, args.retry_attempts +1):
        if result[0] != 'PASS':
            _LOGGER.error('Valkyrie2544.exe Test failed. Please check test config.')
            break
        _LOGGER.info('Verify attempt {}'.format(_))
        old_min = xena_current.min_tput # need this if verify fails
        old_duration = xena_current.duration
        xena_current.modify_2544_tput_options(initial_value=result[1], minimum_value=result[1],
                                              maximum_value=result[1])
        xena_current.modify_duration(args.verify_duration)
        xena_current.write_config('./verify.x2544')
        # run verify step
        _LOGGER.info('Running verify for {} seconds'.format(
            args.verify_duration))
        verify_result = run_xena('./verify.x2544', args.windows_mode)
        if verify_result[0] == 'PASS':
            _LOGGER.info('Verify passed. Packets lost = {} Exiting'.format(
                verify_result[3]))
            _LOGGER.info('Pass result transmit rate = {}'.format(
                verify_result[1]))
            _LOGGER.info('Pass result transmit fps = {}'.format(
                verify_result[2]))
            if args.collect_latency:
                for x in verify_result[4]:
                    _LOGGER.info('Port {}'.format(x.get('ID')))
                    _LOGGER.info('Latency Min = {} micsec'.format(x.get('MinLatency')))
                    _LOGGER.info('Latency Max = {} micsec'.format(x.get('MaxLatency')))
                    _LOGGER.info('Latency Avg = {} micsec'.format(x.get('AvgLatency')))
            break
        else:
            _LOGGER.warning('Verify failed. Packets lost = {}'.format(
                verify_result[3]))
            _LOGGER.info('Restarting Valkyrie2544.exe with new values')
            if args.smart_search:
                new_init = (verify_result[1] - old_min) / 2
            else:
                new_init = result[1] - xena_current.value_thresh
            xena_current.modify_2544_tput_options(
                initial_value=new_init, minimum_value=old_min, 
                maximum_value=result[1] - xena_current.value_thresh)
            xena_current.modify_duration(
                args.search_trial_duration if args.search_trial_duration else
                old_duration)
            _LOGGER.info('New minimum value: {}'.format(old_min))
            _LOGGER.info('New maximum value: {}'.format(
                result[1] - xena_current.value_thresh))
            _LOGGER.info('New initial rate: {}'.format(new_init))
            xena_current.write_config('./verify.x2544')
            result = run_xena('./verify.x2544', args.windows_mode)
    else:
        _LOGGER.error('Maximum number of verify retries attempted. Exiting...')


def read_json_file(json_file):
    """
    Read the json file path and return a dictionary of the data
    :param json_file: path to json file
    :return: dictionary of json data
    """
    try:
        if _PYTHON_2:
            with open(json_file, 'r') as data_file:
                file_data = json.loads(data_file.read())
        else:
            with open(json_file, 'r', encoding=_LOCALE) as data_file:
                file_data = json.loads(data_file.read())
    except ValueError as exc:
        # general json exception, Python 3.5 adds new exception type
        _LOGGER.exception("Exception with json read: %s", exc)
        raise
    except IOError as exc:
        _LOGGER.exception(
            'Exception during file open: %s file=%s', exc, json_file)
        raise
    return file_data


def run_xena(config_file, windows_mode=False):
    """
    Run Valkyrie2544.exe with the config file specified.
    :param config_file: config file to use
    :param windows_mode: enable windows mode which bypasses the usage of mono
    :return: Tuple of pass or fail result as str, and current transmit rate as
    float, transmit fps, and packets lost
    """
    user_home = os.path.expanduser('~')
    log_path = '{}/Xena/Valkrie2544/Logs/valkyrie2544.log'.format(user_home)
    # make the folder and log file if they doesn't exist
    if not os.path.exists(log_path):
        os.makedirs(os.path.dirname(log_path))

    # empty the file contents
    open(log_path, 'w').close()

    # setup the xena command line
    args = ["mono" if not windows_mode else "",
            "Valkyrie2544.exe", "-c", config_file, "-e", "-r", "./", "-u",
            _XENA_USER]

    # Sometimes Valkyrie2544.exe completes, but mono holds the process without
    # releasing it, this can cause a deadlock of the main thread. Use the
    # xena log file as a way to detect this.
    log_handle = open(log_path, 'r')
    # read the contents of the log before we start so the next read in the
    # wait method are only looking at the text from this test instance
    log_handle.read()
    print('XENAVERFIY mono_pipe args: ', args)
    mono_pipe = subprocess.Popen(args, stdout=sys.stdout)
    data = ''
    if _PYTHON_2:
        _LOGGER.error('Not supported yet for python 2...')
    else:
        while True:
            try:
                mono_pipe.wait(60)
                log_handle.close()
                break
            except subprocess.TimeoutExpired:
                # check the log to see if Valkrie2544 has completed and mono is
                # deadlocked.
                data += log_handle.read()
                if 'TestCompletedSuccessfully' in data:
                    log_handle.close()
                    mono_pipe.terminate()
                    break
    
    config = XenaJSON(config_file)
    report = config.filename
    report = report + '.xml'
    # parse the result file and return the needed data
    root = ET.parse(report).getroot()
    return (root[0][1][0].get('TestState'),
            float(root[0][1][0].get('TotalTxRatePcnt')),
            float(root[0][1][0].get('TotalTxRateFps')),
            root[0][1][0].get('TotalLossFrames'),
            root[0][1][0], # return whole element
            )


def write_json_file(json_data, output_path):
    """
    Write out the dictionary of data to a json file
    :param json_data: dictionary of json data
    :param output_path: file path to write output
    :return: Boolean if success
    """
    try:
        if _PYTHON_2:
            with open(output_path, 'w') as fileh:
                json.dump(json_data, fileh, indent=2, sort_keys=True,
                          ensure_ascii=True)
        else:
            with open(output_path, 'w', encoding=_LOCALE) as fileh:
                json.dump(json_data, fileh, indent=2, sort_keys=True,
                          ensure_ascii=True)
        return True
    except ValueError as exc:
        # general json exception, Python 3.5 adds new exception type
        _LOGGER.exception(
            "Exception with json write: %s", exc)
        return False
    except IOError as exc:
        _LOGGER.exception(
            'Exception during file write: %s file=%s', exc, output_path)
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--config_file', type=str, required=True,
                        help='Xena/Valkyrie 2544 json config file name')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Enable debug logging')
    parser.add_argument('-w', '--windows_mode', required=False,
                        action='store_true', help='Use windows mode, no mono')
    parser.add_argument('-l', '--verify_duration', required=False,
                        type=int, default=600,
                        help='Verification duration in seconds')
    parser.add_argument('-r', '--retry_attempts', type=int, default=5,
                        required=False, help='Maximum verify attempts')
    parser.add_argument('-s', '--smart_search', action='store_true',
                        required=False, help='Enable smart search',
                        default=False)
    parser.add_argument('-p', '--pdf_output', action='store_true',
                        required=False,
                        help='Generate PDF report, do not use on Linux!',
                        default=False)
    parser.add_argument('-t', '--search_trial_duration', required=False,
                        help='Search trial duration in seconds', type=int,
                        default=0)
    parser.add_argument('-z', '--collect_latency', required=False,
                        help='Enable Latency counters', action='store_true',
                        default=False)
    parser.add_argument('-k', '--packet_sizes', required=False, nargs='+',
                        type=int, default=False,
                        help='Specify custom packet sizes for test')
    parser.add_argument('-a', '--acceptable_loss', required=False, type=float,
                        help='Specify acceptable loss in terms of percent of packages lost')
    parser.add_argument('-v', '--save_file_name', required=False, type=str,
                        default='./2bUsed.x2544', 
                        help='File name to save new config file as')
    parser.add_argument('-i', '--initial_tput', required=False, type=float,
                        help='Specify initial throughput for test')
    parser.add_argument('-M', '--max_tput', required=False, type=float,
                        help='Specify maximum throughput for test')
    parser.add_argument('-m', '--min_tput', required=False, type=float,
                        help='Specify minimum throughput for test')
    parser.add_argument('-n', '--mac_address', required=False, nargs='+',
                        type=str, help='Set src and destination mac address')
    parser.add_argument('-c', '--connection_ips', required=False, nargs='+',
                        type=str, help='Set src and destination ip address')
    parser.add_argument('-o', '--resolution_tput', required=False, type=float,
                        help='Specify resolution rate for throughput test')
    parser.add_argument('-u', '--flow_count', required=False, choices=list(_FLOWS.keys()),
                        help='Choose number of flows to run')
    parser.add_argument('-b', '--use_both_flows', required=False, 
                        default=False, action='store_true',
                        help='Use value passed to --flow_count for both MAC and IP does not work for 100k and 1M')
    parser.add_argument('-e', '--use_mac_flows', required=False, 
                        default=False, action='store_true', 
                        help='Use value passed to --flow_count for MAC')
    parser.add_argument('--module', required=False, type=int, dest='module',
                        help='Set module number to use for test')

    args = parser.parse_args()
    print('XENAVERFIY ARGS: ', args)
    if args.debug:
        print("DEBUG ENABLED!!!")
    main(args)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
