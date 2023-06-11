NOTE: This application prototype was tested on windows 11. Testing on Mac is still pending.

# Installation

1. Install npcap:
    npcap : https://npcap.com/#download
    npcap for windows : https://npcap.com/dist/npcap-1.75.exe


2. In this directory, open a terminal(as admin), and run the following command to install the required python packages:
    ```
    pip install -r requirements.txt

    ```
    NOTE: If you are getting errors while installing the packages, try updating pip.


3. Usage:

    Application can be run with the following options:

    ```
    usage: main.py [-h] [-r REALTIME | -f FILE] [--generate_false_attacks] [-i INTERFACE]

    options:
    -h, --help            show this help message and exit

    -r REALTIME, --realtime REALTIME
                            Give a time limit for Real time log collection and detection, default is None (infinite).

    -f FILE, --file FILE  
                            Instead of real time log collection, Give a file path to analyse logs present in it.

    --generate_false_attacks
                            Choose whether to generate false attacks(for testing) during the real time detection or not. default is False.

    -i INTERFACE, --interface INTERFACE
                            Network interface to capture packets from. By default, the program will try to automatically detect the active network interface.

    ```

4. Examples:

    ```
    python main.py  
                        :  Run the application in real time detection mode, indefinitely, with default options. (press Ctrl+C to stop the application)

    python main.py -r 60 --generate_false_attacks  
                        :  Run the application in real time detection mode, for 60 seconds, with false attacks generation enabled for testing purposes.

    python main.py -i "Ethernet"  
                        :  Run the application in real time detection mode, indefinitely, with default options, but capture packets from the given network interface (Ethernet).

    python main.py -i "Wi-Fi"  
                        :  Run the application in real time detection mode, indefinitely, with default options, but capture packets from the given network interface (Wi-Fi).

    python main.py -f "./testing_datasets/heartbleed_data.csv"  
                        :  Run the application in file analysis mode, and analyse the given file.


    ```