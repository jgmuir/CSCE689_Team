import pickle
import pefile
from defender.classifier import create_validation_feature_vectors,create_training_feature_vectors

# Load the saved model
with open('model.sav', 'rb') as f:
    model = pickle.load(f)


    train, selected_byte_features, selected_opcode_features_1, selected_opcode_features_2 = create_training_feature_vectors("defender/pe-machine-learning-dataset")
    test = create_validation_feature_vectors('defender/pe-machine-learning-dataset', selected_byte_features, selected_opcode_features_1, selected_opcode_features_2)
    x_test = test.loc[:, test.columns != "CLASSIFICATION"]
    x_test = x_test.drop(columns=["SAMPLE"])
    # Make a prediction using the loaded model
    prediction = model.predict(x_test)

    # Print the prediction
    print(prediction)
    print(len(prediction))