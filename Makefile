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

encrypt:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -e ./testFiles/testFile.txt

decrypt:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -d ./testFiles/testFile.txt.crypt

info: 
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -i ./testFiles/testFile.txt.crypt

check:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -c ./testFiles/testFile.txt.crypt