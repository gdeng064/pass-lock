#!/bin/bash

# Install required packages
echo "Installing dependencies..."
pip install cryptography

# Generate and set Fernet encryption token if not present
TOKEN_FILE="fernet_token.dat"
if [ ! -f "$TOKEN_FILE" ]; then
    echo "Generating encryption token..."
    echo "Python Path: $(which python3)"  # Explicit check to confirm Python path
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > "$TOKEN_FILE"
    echo "Encryption token saved to $TOKEN_FILE."
else
    echo "Encryption token already exists. Using the existing token."
fi

# Export the Fernet key as an environment variable
export FERNET_KEY=$(cat "$TOKEN_FILE")
echo "Fernet encryption key set as an environment variable."

# Persist the environment variable in the shell profile
echo "export FERNET_KEY=$(cat "$TOKEN_FILE")" >> ~/.bashrc

# Final message for setup completion
echo "Setup complete! You can now run the application using:"
echo "python3 src/pass-guard.py"
echo "To use the FERNET_KEY in future sessions, run 'source ~/.bashrc'."

