/**
* Copyright (C) 2016 Verizon. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

Verizon Digital Media Services Token-Based Authentication Version 3.0
Copyright (C) Verizon.  All rights reserved.

Use of source and binary forms, with or without modification is permitted provided
that there is written consent by Verizon. Redistribution in source and binary
forms  is not permitted.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


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
