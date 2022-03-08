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
	find -name *.enc -type f -delete
	mv ./testFiles/testFolder2 ./testFiles/testFolder
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -e ./testFiles/testFile.txt

encryptf:
	find -name *.enc -type f -delete
	mv ./testFiles/testFolder2 ./testFiles/testFolder
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -ef ./testFiles/testFile.txt

decrypt:
	mv ./testFiles/testFolder ./testFiles/testFolder2
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -d ./testFiles/testFile.txt.crypt

decryptf:
	mv ./testFiles/testFolder ./testFiles/testFolder2
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -df ./testFiles/testFile.txt.crypt

info: 
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -i ./testFiles/testFile.txt.crypt

check:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -c ./testFiles/test.crypt

debug:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/main2.cpp --no-warnings -lcrypto
	./build/$(OUTPUT_FILE)

reset: 
	rm -rf ./testFiles/testFolder
	rm -rf ./testFiles/testFolder2
	rm ./testFiles/testFolder.crypt
	mkdir -p ./testFiles/testFolder
	echo "A big test file inside test folder!!!" > ./testFiles/testFolder/test.txt
	mkdir -p ./testFiles/testFolder/testFolder2
	echo "A big test file inside test folder!!!" > ./testFiles/testFolder/testFolder2/test2.txt
	cp /usr/bin/ls ./testFiles/test.txt