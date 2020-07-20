# Frida-GUI-Tool
Frida를 GUI로 사용하기 위한 Tool 입니다.  
Python 3.7에서 만들었습니다.

## 관련 패키지 설치
$ pip install -r requirements.txt  
$ pip install --upgrade -r requirements.txt


## 사용
1. 콘솔창에서 실행  
$ python start.py / py -3 start.py

2. Device 선택  
Tool 시작 직후에 Local system 밖에 안보입니다.  
연결된 장비를 보려면 Search 버튼을 클릭해야 합니다.

3. iOS List는 신경쓰지마세요.  
연결된 장비 이름이 iOS List에 설정된 이름에 있으면 Tool이 장비를 iOS로 인식합니다.

4. 스크립트를 수정할 프로그램 선택

5. 분석할 APP 선택  
Load List 버튼을 누르고, 대상 APP을 더블 클릭 하세요.  
분석할 APP을 확실히 하기 위해 반드시 Save 버튼을 클릭해야 합니다.

6. Analysis Tab으로 이동하고 Hooking Opitons을 설정하세요.  
설정을 확실히 하기 위해 Save 버튼을 클릭하세요.

## Hooking Script / Python Script
1. Hooking Script  
Javascsript / Typescript 입니다. 이 스크립트들은 분석을 끝내거나 다시 분석하기 전까지 동작합니다.  
분석을 시작할 떄 선택한 스크립트들을 합치므로, 이를 고려해서 사용해주세요.  
스크립트를 결합할 때, "Java.perform" 이나 "if(ObjC.available)"을 사용하지 않습니다.  
이것도 고려해주세요.

2. Python Script  
Python Script 입니다. 이 스크립트들은 새로운 프로세스에서 동작합니다(Python subprocess).  
frida example script 처럼 전체 python script를 작성해야하며, 예시를 scripts/python directory에 남겨놨습니다.