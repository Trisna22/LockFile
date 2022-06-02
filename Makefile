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

encrypt:
	find -name *.enc -type f -delete
	mv ./testFiles/testFolder2 ./testFiles/testFolder
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -e ./testFiles/testFolder

decrypt:
	mv ./testFiles/testFolder ./testFiles/testFolder2
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -d ./testFiles/testFolder.crypt

info: 
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -i ./testFiles/testFolder.crypt

check:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -c ./testFiles/testFolder.crypt

debug:
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/main.cpp -ggdb3 --no-warnings -lcrypto
	./build/$(OUTPUT_FILE)

test:
	rm -rf ./testFiles/testFolder
	rm -rf ./testFiles/testFolder2
	rm ./testFiles/testFolder.crypt
	mkdir -p ./testFiles/testFolder
	echo "A big test file inside test folder!!!" > ./testFiles/testFolder/test.txt
	mkdir -p ./testFiles/testFolder/testFolder2
	echo "A very large file" > ./testFiles/testFolder/testFolder2/test2.txt
	cp /usr/bin/ls ./testFiles/testFolder/testFolder2/ls_example

	find -name *.enc -type f -delete
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -e ./testFiles/testFolder

	mv ./testFiles/testFolder ./testFiles/testFolder2
	$(CC) -o $(BUILD_FOLDER)/$(OUTPUT_FILE) $(SOURCE_FOLDER)/$(MAIN_FILE) --no-warnings -lcrypto
	./build/$(OUTPUT_FILE) -d ./testFiles/testFolder.crypt

	diff -r ./testFiles/testFolder2 ./testFiles/testFolder

	diff ./testFiles/testFolder/testFolder2/ls_example /usr/bin/ls

reset: 
	rm -rf ./testFiles/testFolder
	rm -rf ./testFiles/testFolder2
	rm ./testFiles/testFolder.crypt
	mkdir -p ./testFiles/testFolder
	echo "A big test file inside test folder!!!" > ./testFiles/testFolder/test.txt
	mkdir -p ./testFiles/testFolder/testFolder2
	echo "A very large file" > ./testFiles/testFolder/testFolder2/test2.txt
	cp /usr/bin/ls ./testFiles/testFolder/testFolder2/ls_example
