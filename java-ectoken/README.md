EdgeCast Token Authentication extension for Java
================================================

Files included in this release:
ECToken.java
README.txt

================================================
To build:
javac -cp ".:./lib/bcprov-jdk15on-152.jar:./lib/commons-codec-1.10.jar" ECToken.java
jar cfm ECToken.jar ECToken.mf *.class

also see build.sh script

================================================
To deploy:
Copy ECToken.class into $CLASSPATH

================================================
Usage:

ECToken.encryptv3(key, message)

ECToken.decryptv3(key, message)

You can also call it from the command-line:

> java -jar ECToken.jar encrypt IM_A_KEY IM_A_STRING
9g3aUbe15BktzfNZKFhJDie90KRtQhG2_Z9kjEBB7C0Zp6AkJ3wwsqZOdA
> java -jar ECToken.jar decrypt IM_A_KEY 9g3aUbe15BktzfNZKFhJDie90KRtQhG2_Z9kjEBB7C0Zp6AkJ3wwsqZOdA
IM_A_STRING

Follow the instructions in the EdgeCast Token Authentication 1.4 guide. Pass
the above function your key as the first parameter (key), and all of your
token authentication parameters as the second (message). ECToken.encrypt will
return your token as a string. On error this function will return null, and in
most cases throw an Exception. Please note that in this release the maximum
length of message is 512 characters.
