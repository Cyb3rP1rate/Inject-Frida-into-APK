#!/bin/bash

# adapted to shell by chatgpt4, seems to work

BASENAME="apktool_"
JAVA_EXE="java"

if [[ -n $JAVA_HOME ]]; then
  JAVA_EXE="$JAVA_HOME/bin/java"
fi

# Change to script's directory
cd "$(dirname "$0")"

# Find the highest version .jar available in the same directory as the script
if [[ -e apktool.jar ]]; then
    BASENAME="apktool"
else
    MAX_VER=$(ls ${BASENAME}*.jar 2>/dev/null | sort -V | tail -n 1)
    BASENAME=$(basename $MAX_VER .jar)
fi

# Find out if the command line is a parameterless .jar or directory, for fast unpack/repack
FAST_COMMAND=""
if [[ $# -eq 1 ]]; then
  if [[ -d $1 ]]; then
    # Directory, rebuild
    FAST_COMMAND="b"
  elif [[ $1 == *.apk ]]; then
    # APK file, unpack
    FAST_COMMAND="d"
  fi
fi

# Execute command
$JAVA_EXE -Duser.language=en -Dfile.encoding=UTF8 -jar "${BASENAME}.jar" $FAST_COMMAND $@

# Pause when ran non-interactively
if [[ $- != *i* ]]; then
  read -p "Press [Enter] key to continue..."
fi