#	Project:	LockFile
#	Author:		ramb0
#	Version:	1.0

CC=g++
OUTPUT_FILE=LockFile
MAIN_FILE=main.cpp
SOURCE_FOLDER=./src
BUILD_FOLDER=./build

default:
	mkdir -p ./build/
	mkdir -p ./src/
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto

run:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -e ./testFile.txt