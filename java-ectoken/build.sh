#!/bin/bash

javac -cp ".:./lib/bcprov-jdk15on-152.jar:./lib/commons-codec-1.10.jar" ECToken3.java
jar cfm ECToken3.jar ECToken3.mf *.class
