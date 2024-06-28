import json
import logging
import os
import resource
import sys
import time
import traceback
from collections import Counter

import joblib
import argparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_extraction.text import HashingVectorizer

cfg = {}
paths = {}
data = {}
buffer = []
padding = []
window_id = 0

log_path = ''
current_dir = os.path.dirname(os.path.realpath(__file__))
config_path = os.path.join(current_dir, "config.json")
ml_model_path = os.path.join(current_dir, "models/random_forest_model.pkl")
encoder_path = os.path.join(current_dir, "models/ordinal_encoder.pkl")
max_window_length = -1

core_count = 4


def limit_cpu():
    os.sched_setaffinity(0, set(range(0, core_count)))


def limit_memory(maxsize):
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))


def is_file_empty(file_path):
    """Check if file is empty by confirming if its size is 0 bytes"""
    # Check if file exist and it is empty
    return os.path.exists(file_path) and os.stat(file_path).st_size == 0


def add_to_buffer(log_line):
    if cfg["window"]:
        if len(buffer) >= cfg["window_size"]:
            evaluate_current_window()
    else:
        if len(buffer) > 0:
            if int(buffer[0].slpit("|")[1]) - log_line.slpit("|")[1] > cfg["window_size"]:
                evaluate_current_window()

    buffer.append(log_line)


def evaluate_current_window():
    if len(buffer) > 0:
        evaluation_function(str(time.time_ns()), buffer)
        cfg = load_config()
        for _ in range(cfg["stride"]):
            buffer.pop(0)


def get_data_files():
    malware_traces_path = log_path + "/malware"
    goodware_traces_path = log_path + "/goodware"
    # Get a list of all filenames in the folder
    malware_traces = os.listdir(malware_traces_path)
    goodware_traces = os.listdir(goodware_traces_path)
    paths["malware"] = malware_traces
    paths["goodware"] = goodware_traces


def load_config(training=False):
    f = open(config_path)

    # returns JSON object as
    # a dictionary
    global cfg
    cfg = json.load(f)
    if training:
        cfg["evaluation_mode"] = False
    # Closing file
    f.close()
    return cfg


def length_window(my_dict):
    global max_window_length
    for i in my_dict.keys():
        data[i] = {}
        for j in my_dict[i].keys():
            data[i][j] = []
            k = 0
            while k < len(my_dict[i][j]):
                window = []
                limit = (
                    k + cfg["window_size"]
                    if k + cfg["window_size"] < len(my_dict[i][j])
                    else len(my_dict[i][j])
                )
                for l in range(k, limit):
                    if my_dict[i][j][l]:
                        my_dict[i][j][l].pop(0)
                        window.extend(my_dict[i][j][l])
                data[i][j].append(window)
                max_window_length = max(max_window_length, len(window))
                if cfg["evaluation_mode"]:
                    break
                k += cfg["stride"]


def find_start_timestamp(i, j, my_dict, timestamp):
    for k in range(len(my_dict[i][j])):
        try:
            timestamp = int(my_dict[i][j][k][0])
            break
        except:
            continue
    return timestamp


def pad_windows_to_max():
    for i in data.values():
        for j in i.values():
            for k in j:
                # print(max_window_length - len(k))
                for _ in range(max_window_length - len(k)):
                    k.append("")


def window_data(my_dict):
    length_window(my_dict)

    for i in data.keys():
        for j in data[i].keys():
            for k in data[i][j]:
                if max_window_length == len(k):
                    # print(max_window_length)
                    pass
    pad_windows_to_max()


def remove_all_params(my_dict):
    params_to_keep = ['function', 'timestamp']
    keys_to_remove = []
    for key in my_dict.keys():
        if key not in params_to_keep:
            keys_to_remove.append(key)
    for key in keys_to_remove:
        remove_param_by_key(my_dict, key)


def remove_params(my_dict):
    for param in cfg["ignore_list"]:
        remove_param_by_key(my_dict, param)


def remove_param_by_key(my_dict, param):
    my_dict.pop(param, None)


def load_from_files():
    my_dict = {}
    for i in paths.keys():
        my_dict[i] = {}
        for j in paths[i]:
            get_single_file_data(i, j, my_dict)

    return my_dict


def get_single_file_data(i, j, my_dict):
    file_path = log_path + "/" + i + "/" + j
    if not is_file_empty(file_path):
        my_dict[i][j] = []
        lines = open(file_path).readlines()
        for k in lines:
            try:
                if "|" in k:
                    split_values = k.strip().split("|")
                    # print(split_values)

                    result_dict = {
                        split_values[i]: split_values[i + 1]
                        for i in range(0, len(split_values), 2)
                    }
                    remove_headers(result_dict)
                    my_dict[i][j].append(list(result_dict.values()))

                else:
                    k = k.strip()
                    if k.startswith("[INFO]") and k.endswith(":before"):
                        func_name = k.split(" ")[-1].split(":")[0]
                        my_dict[i][j].append([0, func_name])

            except Exception as e:
                # print("Error parsing line")
                pass

def parse_from_memory(window_id, data_array):
    my_dict = {}
    my_dict["live_software"] = {}
    my_dict["live_software"][window_id] = []
    for k in data_array:
        split_values = k.strip().split("|")
        result_dict = {
            split_values[i]: split_values[i + 1] for i in range(0, len(split_values), 2)
        }
        my_dict["live_software"][window_id].append(result_dict)

    return my_dict


def clean_data(my_dict):
    window_data(my_dict)


def remove_headers(my_dict):
    remove_all_params(my_dict)


def order_data(encoder):
    X, y = create_input()
    X_encoded = [' '.join(sublist) for sublist in X]
    X_encoded = encoder.fit_transform(X_encoded)
    # y_encoded = encoder.fit_transform(y)
    return X_encoded, y


def create_input():
    X = []
    y = []
    # size_in_bytes = sys.getsizeof(data)
    # print(f"Size in bytes: {size_in_bytes}")
    for label in data.keys():
        for i in data[label].keys():
            # print(len(data[label][i]))
            for j in data[label][i]:
                X.append(j)
                y.append(label)
    return X, y


def evaluate_ml(pipe):
    load_config()
    while True:
        message = pipe.recv()
        message = str(message).strip()
        print(f"ML received: {message}")
        add_to_buffer(message)
        if message.endswith("Finishing"):
            evaluate_current_window()
            break  # Exit the loop if a termination signal is received


def evaluation_function(window_id, buf):
    my_dict = parse_from_memory(window_id, buf)

    clean_data(my_dict)

    rf_classifier = joblib.load(ml_model_path)
    encoder = joblib.load(encoder_path)
    X, y = order_data(encoder)
    y = rf_classifier.predict(X)
    y_reversed = list(map(lambda a: cfg["categories"][int(a)], y))

    print("ML Predicted:{}".format(y_reversed))
    logging.info("ML Predicted:{}".format(y_reversed))


def train():
    rf_classifier = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42, verbose=1)
    encoder = HashingVectorizer()
    X, y = order_data(encoder)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    print("Training the classifier...")
    rf_classifier.fit(X_train, y_train)

    y_pred = rf_classifier.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy * 100:.2f}%")
    logging.info(f"Accuracy: {accuracy * 100:.2f}%")

    report = classification_report(y_test, y_pred)
    print("Classification Report:")
    print(report)
    logging.info("Classification Report:\n{}".format(report))

    joblib.dump(rf_classifier, ml_model_path)
    joblib.dump(encoder, encoder_path)

    return rf_classifier, encoder


def test(rf_classifier, encoder):
    global paths
    paths = {}
    malware_traces_path = log_path + "/test"
    # Get a list of all filenames in the folder
    malware_traces = os.listdir(malware_traces_path)
    paths["test"] = malware_traces

    my_dict = {}
    global data

    for i in paths.keys():
        for j in paths[i]:
            my_dict[i] = {}
            data = {}
            get_single_file_data(i, j, my_dict)
            clean_data(my_dict)

            y = predict(rf_classifier, encoder)
            counter = Counter(y)
            label = str(counter.most_common(1)[0][0])
            print(f"File {j} ({label}) Predicted: {counter[label]} / {len(y)}")
            logging.info(f"File {j} ({label}) Predicted: {counter[label]} / {len(y)}")

    my_dict = load_from_files()
    clean_data(my_dict)


def predict(rf_classifier, encoder):
    X, y = order_data(encoder)
    y = rf_classifier.predict(X)
    return y


def training_main():
    load_config()
    get_data_files()
    my_dict = load_from_files()
    clean_data(my_dict)
    rf_classifier, encoder = train()
    test(rf_classifier, encoder)


def test_file(path):
    try:
        with open(path, "r") as file:
            for line in file.readlines():
                line = line.strip()
                if line:
                    add_to_buffer(line)
    except:
        print("Specified file not found")
        logging.error("Specified file not found")


if __name__ == "__main__":
    log_file_name = "ml_" + str(time.time()) + ".log"
    logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s %(message)s')
    try:
        parser = argparse.ArgumentParser(description='Process malware traces path.')
        parser.add_argument('--path',
                            type=str,
                            help='the path to the malware traces')

        # Parse the command line arguments
        args = parser.parse_args()

        log_path = args.path

        limit_cpu()
        GB = 1073741824
        limit_memory(20 * GB)

        load_config(True)

        # Define the --test argument with a description
        parser.add_argument('--test', action='store_true', help='Specify a test file')


        # Parse the command line arguments
        args = parser.parse_args()

        # Check if the --test argument was provided
        if args.test:
            # Access the value of the --test argument using args.test

            rf_classifier = joblib.load(ml_model_path)
            encoder = joblib.load(encoder_path)
            test(rf_classifier, encoder)
        else:
            print('Training started')
            logging.info('Training started')
            training_main()
    except MemoryError as e:
        print(f"A memory error occurred during training: {e}")
        logging.error(f"A memory error occurred during training: {e}")
    except Exception as e:
        print(f"An error occurred during training: {e}")
        logging.error(f"An error occurred during training: {e}")
