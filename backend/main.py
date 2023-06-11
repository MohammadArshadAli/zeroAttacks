from cicflowmeter_log_collector.constants import CONNECTION_PORT
from cicflowmeter_log_collector.sniffer import main_import
from pickle import load
from random import choice
import socketio
import eventlet
import warnings
# from subprocess import Popen, PIPE, DEVNULL, call
from time import sleep
from multiprocessing import Process
# from pyautogui import alert
import numpy as np
from pandas import read_csv
import argparse
import psutil
from os import path

DIRNAME = path.dirname(__file__)
server_process=None
cic_process=None

# NEW_MODEL_PATH = r"./models"
# above one was not working if we call python from another directory, like `python "C:\Users\Mohammad Arshad Ali\Desktop\Programming_not_dropbox\Programming\Kmit\project_school_2_2\zeroAttacks\main.py"`

NEW_MODEL_PATH = path.join(DIRNAME, "models")
attack_names = ['botnet', 'brute_force', 'ddos', 'dos_goldeneye', 'dos_hulk', 'dos_slowhttptest',
                'dos_slowloris', 'ftp_patator', 'heartbleed', 'infiltration', 'portscan', 'sql_injection', 'ssh_patator', 'xss']

attack_files = ['bot_data.csv', 'brute_force_data.csv', 'ddos.csv', 'dos_goldeneye_data.csv', 'dos_hulk_data.csv', 'dos_slowhttptest_data.csv', 'dos_slowloris_data.csv',
                'ftp_patator.csv', 'heartbleed_data.csv', 'infiltration_data.csv', 'portscan_data.csv', 'sql_injection_data.csv', 'ssh_patator.csv', 'xss_data.csv']

attack_models = {}


def warn(*args, **kwargs):
    pass


def load_model(model_name_to_save):
    with open((NEW_MODEL_PATH + rf"/{model_name_to_save}.pkl"), "rb") as f_model:
        return load(f_model)


# not using this function
# def runCicflowmeter(generate_false_attacks):
#     if generate_false_attacks:
#         command = r'cicflowmeter -i "Wi-Fi" -u "hello" -c "./CicFlowMeter_logData" --generate_false_attacks'
#     else:
#         command = r'cicflowmeter -i "Wi-Fi" -u "hello" -c "./CicFlowMeter_logData"'

#     process = Popen(command)  # !, stdout=DEVNULL
#     return process


def runCicflowmeter_from_function(input_interface, generate_false_attacks):
    main_import(input_interface, generate_false_attacks=generate_false_attacks)


for i in range(len(attack_names)):
    attack_models[attack_names[i]] = load_model(attack_files[i].split(".")[0])

warnings.warn = warn  # to supress sklearn warnings

loaded_model = load_model("rf_max_depth20__9983")


# create a Socket.IO server instance
sio = socketio.Server(logger=False, engineio_logger=False)

# create a WSGI app instance
server_app = socketio.WSGIApp(sio)


def start_server(app=server_app):
    # Popen(['eventlet', 'wsgi', '--bind', 'localhost:8001', 'myapp:app'])
    eventlet.wsgi.server(eventlet.listen(('localhost', CONNECTION_PORT)), app)


def detect_attack_type(input_attack):
    detected_attacks = []

    for attack, model in attack_models.items():
        # print(np.array(input_attack))
        if model.predict(np.array(input_attack).reshape(1, -1)) == 1:
            detected_attacks.append(attack)



    if len(detected_attacks) == 0:
        sio.emit("malicious", {"attackType": "Probable Zero day attack"})
        return "Probable Zero day attack."
    
    elif len(detected_attacks) == 1:
        sio.emit("malicious", {"attackType": detected_attacks[0]})
        return detected_attacks[0]
    
    else:
        sio.emit("malicious", {"attackType": choice(detected_attacks)})
        return "Multiple possible attacks detected : " + ", ".join(detected_attacks)


def second_ml_layer(pred):
    # print(pred)
    for i in range(len(pred)):
        print("{}".format(detect_attack_type(pred[i])))
    print("\n\n")

# event handlers for Socket.IO server

# an event handler for the 'connect' event

@sio.event
def connect(sid, environ):
    print('Client connected:', sid)

# an event handler for the 'disconnect' event


@sio.event
def disconnect(sid):
    print('Client disconnected:', sid)


@sio.event
def electron(sid, data):
    if data == "stop":
        print(f" electron says {data}")
        # server_process.terminate()
        # cic_process.terminate()
        # terminate_server_and_cicflowmeter() #!!
        # exit()
    return("stopped")

# an event handler for a custom event


@sio.event
def CicFlowMeter(sid, data):
    # print(f" CICFlowMeter : {data}")
    if len(data["data"][0]) != 0:
        pred = loaded_model.predict(data["data"])

        if pred.any() == False:
            print("    : All Benign connections..\n\n")
        else:
            pred_unique = np.unique(pred, return_counts=True)

            if len(pred_unique[0]) == 1:
                n_malicious = pred_unique[1][0]
            else:
                n_malicious = np.unique(pred, return_counts=True)[1][1]
            print("    : {} malicious logs detected.\n\n".format(n_malicious))
            second_ml_layer(np.array(data["data"])[pred == 1])
            # alert("{} malicious logs detected.".format(n_malicious))
    # alert(unique(loaded_model.predict(data["data"]), return_counts=True))


# start the server and cicflowmeter
def start_server_and_cicflowmeter(input_interface, generate_false_attacks, minutes=None):
    # server=eventlet.wsgi.server(eventlet.listen(('localhost', 8001)), app)
    global server_process, cic_process

    server_process = Process(target=start_server)
    # start_server_and_cicflowmeter.server_process = server_process

    server_process.start()
    sleep(4)

    # process = runCicflowmeter(generate_false_attacks)
    cic_process = Process(target=runCicflowmeter_from_function,
                      args=(input_interface, generate_false_attacks))

    # start_server_and_cicflowmeter.process = process
    cic_process.start()

    # PROCESSES.extend([server_process, process])
    


    try:
        if minutes is not None:
            sleep(60*minutes)
            server_process.terminate()
            cic_process.terminate()

        else:  # running infinitely #!!!
            while True:
                pass

    except KeyboardInterrupt:
        server_process.terminate()
        cic_process.terminate()
        print("Server and Cicflowmeter terminated.")





def analyse_logs_from_file(path):
    df = read_csv(path)
    df = (df.drop(columns=["label"])) if "label" in df.columns else (df)

    pred = loaded_model.predict(df)

    if pred.any() == False:
        print("\nAll Benign connections..\n\n")
    else:
        pred_unique = np.unique(pred, return_counts=True)

        if len(pred_unique[0]) == 1:
            n_malicious = pred_unique[1][0]
        else:
            n_malicious = np.unique(pred, return_counts=True)[1][1]
        print("{} malicious logs detected, out of {}".format(
            n_malicious, pred.shape[0]))
        # alert("{} malicious logs detected, out of {}".format(n_malicious, pred.shape[0]))
        second_ml_layer(df.values[pred == 1])


def get_active_interface():
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'ESTABLISHED':
            local_ip = conn.laddr.ip
            for interface, addresses in psutil.net_if_addrs().items():
                if interface == 'Loopback Pseudo-Interface 1':
                    continue
                for address in addresses:
                    if address.address == local_ip:
                        print(f"Network interface detected: {interface}")
                        return interface

    print("No network interface detected.")
    return None


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=False)

    # give an option that can recieve an optional argument

    group.add_argument(
        "-r",
        "--realtime",
        action="store",
        dest="realtime",
        default=None,
        help="Give a time limit for Real time log collection and detection, default is None (infinite).",
    )
    group.add_argument(
        "-f",
        "--file",
        action="store",
        default=None,
        dest="file",
        help="Instead of real time log collection, Give a file path to analyse logs present in it.",
    )

    parser.add_argument(
        "--generate_false_attacks",
        action="store_true",
        dest="generate_false_attacks",
        default=False,
        help="Choose whether to generate false attacks(for testing) during the real time detection or not. default is False.",
    )

    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        default=None,
        help="Network interface to capture packets from. By default, the program will try to automatically detect the active network interface.",
    )

    args = parser.parse_args()

    if args.file is None:

        if args.realtime is None:
            MINUTES = None
        else:
            MINUTES = int(args.realtime)

        if args.interface is None:
            interface = get_active_interface()
            if interface is None:
                print("Automatic detection of network interface failed. Please specify a network interface using -i or --interface.\n Example: python main.py -i \"Wi-Fi\"")
                # exit()
                assert interface, "Select a network interface using -i or --interface."
        else:
            interface = args.interface
        start_server_and_cicflowmeter(
            interface, args.generate_false_attacks, MINUTES)

    else:
        analyse_logs_from_file(args.file)
