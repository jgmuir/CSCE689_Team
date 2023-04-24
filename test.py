import pickle
import pefile
from defender.classifier import create_classification_feature_vector

# Load the saved model
with open('model.sav', 'rb') as f:
    model = pickle.load(f)


    features = create_classification_feature_vector("defender/pe-machine-learning-dataset/samples/2", "selected_features.txt")

    print(features.shape)
    # Make a prediction using the loaded model
    prediction = model.predict(features)

    # Print the prediction
    print(prediction[0])