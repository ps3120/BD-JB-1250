JAR_NAME := Poops.jar

MAKEFILE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BDJSDK_HOME  ?= $(MAKEFILE_DIR)/../../../../
JAVA8_HOME    ?= $(BDJSDK_HOME)/host/jdk8
JAVAC        := $(JAVA8_HOME)/bin/javac
JAR          := $(JAVA8_HOME)/bin/jar

export JAVA8_HOME

CLASSPATH     := $(BDJSDK_HOME)/target/lib/enhanced-stubs.zip:$(BDJSDK_HOME)/target/lib/bdjstack.jar:$(BDJSDK_HOME)/target/lib/rt.jar:../../discdir/BDMV/JAR/00000.jar:../../src/
SOURCES       := $(wildcard src/org/bdj/external/*.java)
JFLAGS        := -Xlint:-options -source 1.4 -target 1.4

all: $(JAR_NAME)

# Create JAR with manifest
$(JAR_NAME): $(SOURCES) manifest.txt
	$(JAVAC) $(JFLAGS) -cp $(CLASSPATH) $(SOURCES)
	$(JAR) cfm $@ manifest.txt -C src/ .

clean:
	rm -f src/org/bdj/external/*.class $(JAR_NAME)
