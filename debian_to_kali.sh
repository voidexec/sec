#!/bin/bash

# Update package list and install necessary tools
sudo apt -y update
sudo apt -y install wget gnupg dirmngr

# Download and add Kali repository key
wget -q -O - https://archive.kali.org/archive-key.asc | sudo tee /etc/apt/trusted.gpg.d/kali.asc

# Edit sources.list to add Kali repository
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list

# Update the package list again after changing the sources
sudo apt -y update

# Upgrade all packages
sudo apt -y upgrade

# Perform a full distribution upgrade
sudo apt -y dist-upgrade

# Remove unused packages
sudo apt -y autoremove --purge

# Install Kali Linux everything package
sudo apt -y install kali-linux-everything
