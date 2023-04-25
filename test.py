import os
import requests
import numpy as np

def process_files(path):
    confusion_matrix = np.zeros((2, 2), dtype=int)

    for root, _, files in os.walk(path):
        for file in files:
                filepath = os.path.join(root, file)

                with open(filepath, 'rb') as f:
                    data = f.read()
                
                response = requests.post(
                    "http://127.0.0.1:8080/",
                    data=data,
                    headers={"Content-Type": "application/octet-stream"}
                )
                
                result = int(response.json()['result'])
                true_label = 'gw' in root
                
                if true_label and result == 0:
                    confusion_matrix[0, 0] += 1
                elif true_label and result == 1:
                    confusion_matrix[0, 1] += 1
                elif not true_label and result == 0:
                    confusion_matrix[1, 0] += 1
                elif not true_label and result == 1:
                    confusion_matrix[1, 1] += 1

    return confusion_matrix

if __name__ == '__main__':
    base_path = "defender/pe-machine-learning-dataset"
    confusion_matrix = process_files(base_path)
    print(confusion_matrix)