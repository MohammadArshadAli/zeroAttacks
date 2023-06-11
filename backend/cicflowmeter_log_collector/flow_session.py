from .flow import Flow 
from .features.context.packet_flow_key import get_packet_flow_key 
from .features.context.packet_direction import PacketDirection 
from scapy.sessions import DefaultSession
# import requests
from collections import defaultdict
import csv
# from json import dump
import pickle
from .features.send_to_server import Client 
from .constants import CONNECTION_PORT


EXPIRED_UPDATE = 40
# EXPIRED_UPDATE = 4
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100

#!!!!!!!


def save_object(obj, filename):
    with open(filename, 'wb') as outp:  # Overwrites any existing file.

        # print("Insaveobj")
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)

#!!!!!!


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):

        print("Cicflowmeter initialised..")
        #!!!!!!!
        try:
            self.connection_to_server = Client(CONNECTION_PORT)
        except Exception as e:
            # print(e)
            print("\n\nServer not running\n\n")
            raise e
        # print("inithua")
        #!!!!!!!!!!!!

        self.flows = {}
        self.csv_line = 0

        if self.output_mode == "flow":
            # print("yehhua")
            # output = open(self.output_file, "w")
            # self.output = output
            # self.csv_writer = csv.writer(output)
            pass

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # print("packethua")
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        # print("packetrecievehua")
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)

        # !!! added this as, local variable referrenced before declaration error
        GARBAGE_COLLECT_PACKETS = 200
        if not self.url_model:
            GARBAGE_COLLECT_PACKETS = 10000  # !! previous 10000
        # print("logs colloected :",self.packets_count) ##!!
        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            print("logs collected :", self.packets_count)
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        # print("getflowhua")
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # print("garbagecollecthua")
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        if not self.url_model:
            # print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
            pass
        keys = list(self.flows.keys())
        # print(keys)

        #!!!!!!!!!!

        # print("beforewith")
        # with open(r"C:\Users\sbtal\Desktop\rachittttt.json","w") as f:

        #     dump(self.flows,f,indent=2,)
        #     print("Inwith")
        # save_object(
        #     self.flows, r"C:\Users\Mohammad Arshad Ali\Desktop\testoutput.pkl")
        # print("Outwith")

        #!!!!!!!!!!

        data_for_server = {"data": [],
                           "columns": ['dst_port', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max',
                                       'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
                                       'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'pkt_len_max', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_std',
                                       'pkt_len_var', 'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min', 'fwd_act_data_pkts', 'fin_flag_cnt',
                                       'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 'fwd_byts_b_avg', 'fwd_pkts_b_avg',
                                       'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'fwd_seg_size_avg', 'bwd_seg_size_avg', 'subflow_fwd_byts',
                                       'subflow_bwd_byts', 'subflow_fwd_pkts', 'subflow_bwd_pkts']}
        for k in keys:
            # print("In for")
            flow = self.flows.get(k)

            # print((latest_time - flow.latest_timestamp),
            #       (flow.duration > 90), sep="\n\n")
            if (
                (latest_time is None)
                # TODO:lmkhgcf
                or (latest_time - flow.latest_timestamp > EXPIRED_UPDATE)
                or (flow.duration > 90)  # !!!!!!!!!!!!!!!!!!
                or True  # !!!!!!!!!!!!!!!!!!!!
            ):
                # print("In Bigggggg")
                data = flow.get_data()

                # POST Request to Model API
                if self.url_model:
                    # print("Hellomnn")

                    payload_data = list(data.values())

                    # payload = {
                    #     "columns": list(data.keys()),
                    #     "data": [list(data.values())],
                    # }

                    # print("\n\n")
                    # print(payload)
                    # input("\n\ninput please: ")

                    #!!!!!!!!!!
                    # post = requests.post(
                    #     self.url_model,
                    #     json=payload,
                    #     headers={
                    #         "Content-Type": "application/json; format=pandas-split"
                    #     },
                    # )

                    #!! my code below

                    data_for_server['data'].append(payload_data)
                    #!!!!!!!!!!

                    #! below code expects a response from the machine learning model api
                    # resp = post.json()
                    # result = resp["result"].pop()
                    # if result == 0:
                    #     result_print = "Benign"
                    # else:
                    #     result_print = "Malicious"

                    # print(
                    #     "{: <15}:{: <6} -> {: <15}:{: <6} \t {} (~{:.2f}%)".format(
                    #         resp["src_ip"],
                    #         resp["src_port"],
                    #         resp["dst_ip"],
                    #         resp["dst_port"],
                    #         result_print,
                    #         resp["probability"].pop()[result] * 100,
                    #     )
                    # )
                    #! above code expects a response from the machine learning model api

                # if self.csv_line == 0:
                #     self.csv_writer.writerow(data.keys())

                # self.csv_writer.writerow(data.values())
                # self.csv_line += 1
                # print("HIII")
                # self.output.close()  # TODO: !!!!!!!!

                del self.flows[k]

        #!!!!!!!!!!!!!!!
        self.connection_to_server.sendToServer("CicFlowMeter", data_for_server,self.generate_false_attacks)
        print("sent to server, from Cicflowmeter...  ",end=" ")

        #!!!!!!!!!!!!!!!
        if not self.url_model:
            # print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))
            pass
        # print(1000/0)


def generate_session_class(output_mode, output_file, url_model,generate_false_attacks):
    # print("sessiongeneratehua")
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
            "generate_false_attacks":generate_false_attacks,
        },
    )
