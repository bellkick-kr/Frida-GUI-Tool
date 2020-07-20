# Frida-GUI-Tool
Use Frida as GUI
It's made of python 3.7

## Install packages
$ pip install -r requirements.txt  
$ pip install --upgrade -r requirements.txt


## Usage
1. Run on console.  
$ python start.py / py -3 start.py

2. Select Target Device  
After running this tool, It just shows local system.  
So, you need to click the Search button for see lists of connected device.  

3. Doesn't care ios list. It just makes sure what are ios device.  
If you edit this, this tool will regard devices whose name is in ios list as ios device.

4. Set your edit program.

5. Select the app you want to analysis.  
Push the Load List button, and Double click your target app.  
You have to push the Save button to make sure you will analyze the app.

6. Go to Analysis Tab. & Set Hooking Options.  
You have to push the Save button to make sure your options.

## Hooking Script / Python Script
1. Hooking Script  
It's js or ts script. those are run until you finish or restart the analysis.  
And, Selected Script will be combined when you start analyze app.  
You should consider it.  
One more thing, This tool don't use "Java.perform" or "if(ObjC.available)" when combine the selected scripts.  
So also you should consider it.

2. Python Script  
It's your python scripts. those are run as new process(python subprocess).  
You have to make those scripts as whole frida script like basic example of frida script.  
I remain example script in scripts/python directory.