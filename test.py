import pickle
import pefile
from defender.classifier import create_classification_feature_vector,create_training_feature_vectors

# Load the saved model
with open('model.sav', 'rb') as f:
    model = pickle.load(f)


    features = create_training_feature_vectors("defender/pe-machine-learning-dataset")

    print(features.shape)
    # Make a prediction using the loaded model
    prediction = model.predict(features)

    # Print the prediction
    print(prediction[0])