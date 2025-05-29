#!/bin/bash
# Setup script for ETDI Hextra documentation

echo "Setting up ETDI Hextra documentation..."

# Install Hugo if not present
if ! command -v hugo &> /dev/null; then
    echo "Installing Hugo..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install hugo
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install hugo
    else
        echo "Please install Hugo manually: https://gohugo.io/installation/"
        exit 1
    fi
fi

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Initialize Hugo modules
echo "Initializing Hugo modules..."
cd docs-hextra
hugo mod init github.com/python-sdk-etdi/python-sdk-etdi
hugo mod get github.com/imfing/hextra

# Build the site
echo "Building documentation..."
hugo --minify

echo "Setup complete! Run 'npm run dev' to start development server."
echo "Visit http://localhost:1313 to view the documentation." 