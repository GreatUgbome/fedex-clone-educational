#!/bin/bash

# FedEx Clone - Quick Setup and Deployment Script
# This script helps you set up and deploy the FedEx Clone project

set -e

echo "🚀 FedEx Clone - Setup & Deployment Script"
echo "=========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

print_success "Node.js found: $(node --version)"

# Navigate to backend directory
cd backend || {
    print_error "backend directory not found"
    exit 1
}

print_info "Installing dependencies..."
npm install --silent
print_success "Dependencies installed"

# Check if .env exists
if [ ! -f .env ]; then
    print_warning ".env file not found. Creating from .env.example..."
    cp .env.example .env
    print_warning "Please update .env with your MongoDB credentials and email settings"
fi

print_success ".env file exists"

# Test MongoDB connection
print_info "Testing MongoDB connection..."
if grep -q "MONGO_URI" .env; then
    print_success "MONGO_URI found in .env"
else
    print_error "MONGO_URI not found in .env"
fi

# Start server
print_info "Starting backend server..."
print_info "Server will run on http://localhost:5002"
print_info "Press Ctrl+C to stop"
echo ""
npm start

