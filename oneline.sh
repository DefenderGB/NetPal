#!/bin/bash
git clone https://github.com/DefenderGB/NetPal.git
cd NetPal

# Run setup (creates venv, installs dependencies, configures AWS)
bash setup.sh

# Run the app with convenience script
bash run.sh