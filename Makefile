DISC_LABEL := Lapse_1.2_Mod

#
# Host tools
#
MAKEFILE_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BDJSDK_HOME  ?= /home/vittorio/bdj-sdk
BDSIGNER     := $(BDJSDK_HOME)/host/bin/bdsigner
MAKEFS       := $(BDJSDK_HOME)/host/bin/makefs
JAVA8_HOME   ?= $(BDJSDK_HOME)/host/jdk8
JAVAC        := $(JAVA8_HOME)/bin/javac
JAR          := $(JAVA8_HOME)/bin/jar

export JAVA8_HOME

#
# Compilation artifacts
#
CLASSPATH := $(BDJSDK_HOME)/target/lib/enhanced-stubs.zip:$(BDJSDK_HOME)/target/lib/bdjstack.jar:$(BDJSDK_HOME)/target/lib/rt.jar
SOURCES   := $(wildcard src/org/bdj/*.java) $(wildcard src/org/bdj/sandbox/*.java) $(wildcard src/org/bdj/api/*.java)
JFLAGS    := -Xlint:-options -source 1.4 -target 1.4

#
# Disc files
#
TMPL_DIRS  := $(shell find $(BDJSDK_HOME)/resources/AVCHD/ -type d)
TMPL_FILES := $(shell find $(BDJSDK_HOME)/resources/AVCHD/ -type f)

DISC_DIRS := $(patsubst $(BDJSDK_HOME)/resources/AVCHD%,discdir%,$(TMPL_DIRS)) \
             discdir/BDMV/JAR

all: discdir copy_disc_files discdir/BDMV/JAR/00000.jar $(DISC_LABEL).iso

#
# Create disc directories
#
discdir:
	mkdir -p $(DISC_DIRS)

#
# Compile main JAR
#
discdir/BDMV/JAR/00000.jar: discdir $(SOURCES)
	$(JAVAC) $(JFLAGS) -cp $(CLASSPATH) $(SOURCES)
	$(JAR) cf $@ -C src/ .
	@if [ -f payload.jar ]; then \
		echo "Adding payload.jar to 00000.jar under org/bdj/"; \
		mkdir -p tmpdir/org/bdj; \
		cp payload.jar tmpdir/org/bdj/; \
		$(JAR) uf $@ -C tmpdir .; \
		rm -rf tmpdir; \
	fi
	$(BDSIGNER) -keystore $(BDJSDK_HOME)/resources/sig.ks $@

#
# Copy all other disc files preserving folder structure
#
copy_disc_files: discdir
	@for f in $(TMPL_FILES); do \
		dest="discdir$${f#$(BDJSDK_HOME)/resources/AVCHD}"; \
		mkdir -p "$$(dirname "$$dest")"; \
		cp "$$f" "$$dest"; \
	done

#
# Build ISO
#
$(DISC_LABEL).iso:
	$(MAKEFS) -m 16m -t udf -o T=bdre,v=2.50,L=$(DISC_LABEL) $@ discdir

#
# Clean build artifacts
#
clean:
	rm -rf META-INF $(DISC_LABEL).iso discdir src/org/bdj/*.class src/org/bdj/sandbox/*.class src/org/bdj/api/*.class
