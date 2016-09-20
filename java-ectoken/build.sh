#!/bin/bash

# /**
# * Copyright (C) 2016 Verizon. All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */

javac -cp ".:./lib/bcprov-jdk15on-152.jar:./lib/commons-codec-1.10.jar" ECToken3.java
jar cfm ECToken3.jar ECToken3.mf *.class
