
import paho.mqtt.client
from paho.mqtt.client import Client
from pprint import pprint
import ssl
import time
import json

global_status = {}


def get_value(key, d):
    """
    Gets a value in a nested dictionary
    :param key: dot-separated string of keys (Ex: 'one.two.three')
    :param d: dict
    :return: The value in the dict: d['one']['two']['three'] or None
    """
    key_list = key.split(".")
    for k in key_list:
        if k in d:
            d = d[k]
        else:
            return None
    return d


def merge_dicts(src, dst):
    """
    Takes 2 dictionaries and merges them into one. Overwrites common values.
    :param src: dict
    :param dst: dict
    :return: None
    """
    for key in src:
        if key not in dst:
            dst[key] = src[key]
        elif not isinstance(src[key], dict):
            dst[key] = src[key]
        elif isinstance(src[key], dict):
            merge_dicts(src[key], dst[key])


def on_message(mqtt, data_file, msg):
    """
    MQTT message handler. Writes RSSI (received signal strength indicator)
    and X Y location to file if Roomba is active and RSSI is fresh.

    :param mqtt: The client object
    :param data_file: the file object for writing
    :param msg: the message that was received
    :return: None
    """

    # Parse the message (JSON)
    payload = json.loads(msg.payload)

    # Update the global data structure with this messages contents
    merge_dicts(payload, global_status)

    # Get the Roombas' state (one of: none, quick, scheduled?)
    cycle = get_value('state.reported.cleanMissionStatus.cycle', global_status)

    # Proceed if Roomba is not idle
    if cycle != 'none':

        # Get the latest RSSI (this will only happen when an RSSI
        # message is received because we are looking in payload, not global_status)
        rssi = get_value('state.reported.signal.rssi', payload)

        # Proceed if new RSSI
        if rssi is not None:

            # Get the most recent location
            loc = get_value('state.reported.pose.point', global_status)

            if loc is not None:
                print loc, rssi
                data_file.write(str(time.time()) + "," +
                                str(loc['x']) + "," +
                                str(loc['y']) + "," +
                                str(rssi) + "\n")


if __name__ == "__main__":
    import argparse
    import roomba_get_password

    parser = argparse.ArgumentParser()
    parser.add_argument('out_file', required=False, default='roomba.csv', help="Data log file")
    args = parser.parse_args()

    # Get existing config
    (ADDR, BLID, PASS) = roomba_get_password.read_info()

    # If missing config. Get it
    while ADDR is None or BLID is None or PASS is None:
        roomba_get_password.main()
        (ADDR, BLID, PASS) = roomba_get_password.read_info()

    # Open the data file
    data_file = open(args.out_file, 'w')
    data_file.write("Time,X,Y,RSSI\n")

    # ssl TLS context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    # MQTT client
    c = Client(client_id=BLID, userdata=data_file)
    c.on_message = on_message
    c.tls_set_context(ssl_context)
    c.tls_insecure_set(True)
    c.username_pw_set(username=BLID, password=PASS)
    c.connect(ADDR, 8883)

    print "Listening..."
    try:
        c.loop_forever()
    except KeyboardInterrupt:
        pass

    data_file.close()
    c.disconnect()
