#!/bin/bash

for i in *.java #change extension for different languages 
do
  if ! grep -q Copyright $i
  then
    cat copyright.txt $i >$i.new && mv $i.new $i
  fi
done
