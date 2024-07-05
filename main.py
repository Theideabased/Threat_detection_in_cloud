import pandas as pd
from joblib import load
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

# Load the existing model
model = load('next_best_model.pkl')

# Define necessary columns
required_columns = ['src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port']

# Streamlit app
st.title('Network Packet Prediction')

# File upload
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    # Check if the necessary columns are present
    if not all(column in df.columns for column in required_columns):
        st.error(f"CSV file must contain the following columns: {', '.join(required_columns)}")
    else:
        # Drop rows with missing values
        df.dropna(subset=required_columns, inplace=True)

        # Convert IP addresses to numeric values
        df['src_ip'] = df['src_ip'].apply(lambda x: int(''.join([f'{int(i):02X}' for i in x.split('.')]), 16))
        df['dst_ip'] = df['dst_ip'].apply(lambda x: int(''.join([f'{int(i):02X}' for i in x.split('.')]), 16))

        # Ensure proto, src_port, and dst_port are integers
        df['proto'] = df['proto'].astype(int)
        df['src_port'] = df['src_port'].astype(int)
        df['dst_port'] = df['dst_port'].astype(int)

        # Select necessary columns
        X = df[required_columns]

        # Make predictions
        predictions = model.predict(X)

        # Add predictions to the DataFrame
        df['predictions'] = predictions

        # Display the DataFrame
        st.write("Predictions:", df.head())

        # Visualize the results: Count of predictions
        plt.figure(figsize=(10, 6))
        sns.countplot(x='predictions', data=df, palette='viridis')
        plt.title('Count of Predictions')
        plt.xlabel('Prediction')
        plt.ylabel('Count')
        st.pyplot(plt)
else:
    st.info("Please upload a CSV file.")
