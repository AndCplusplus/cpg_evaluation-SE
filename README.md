Document Links: [install](#install) / [usage](#usage) / [demo](#demo)
<img width="1024" height="1024" alt="A graphic-heavy logo" src="https://github.com/user-attachments/assets/57f63bf5-723c-404d-9dbb-34dbb8d74019" />
<center> Vulnerability Scanner<br />
Group project for Software Engineering<br /><br />
</center>


<a name="install">Installation</a>:<br />
Navigate to the directory for the installation and install prerequisites:<br />
1.	sudo apt update<br />
     - Updates the package index so your system knows the latest versions of software available. Without this, installs may fail or pull outdated versions.
2.	sudo apt install curl<br />
     - Provides the curl command-line tool, used to download files or interact with web APIs. It’s often needed for fetching scripts or data (like Joern’s installer).
3.	sudo apt install python3<br />
     - Installs the Python interpreter. Everything else depends on this.
4.	sudo apt install python3-tk<br />
     - Provides the Tkinter GUI toolkit bindings for Python. This is what our app uses to create windows, buttons, dropdowns, and the canvas.<br />
5.	sudo apt install python3-matplotlib<br />
     - Installs Matplotlib, the plotting library used to visualize graphs inside the Tkinter canvas.<br />
6.	sudo apt install python3-pandas<br />
     - Installs Pandas, which is used to store and manipulate vulnerability reports
7.	sudo apt install python3-networkx<br />
     - Installs NetworkX, the graph library is used to build CFG, CALL, and AST graphs from Joern’s CPG data.
8.	sudo apt install -y openjdk-17-jdk<br />
     - Joern is built on the JVM (Java Virtual Machine). Java 17 is needed to run Joern’s CLI tools (joern-parse, joern-export, etc.)
9.	wget https://github.com/joernio/joern/releases/download/v4.0.324/joern-install.sh<br />
     - Downloads Joern’s installer script.
10.	sudo chmod +x joern-install.sh<br />
     - Makes the installer script executable.
11.	sudo ./joern-install.sh –interactive=false<br />
     - Runs the installer in non-interactive mode, so Joern is set up automatically without prompting you.
12. Extract joern-cli.zip<br />
     - Joern’s CLI tools are packaged in a zip file. Extracting it gives you access to commands, which our app calls to generate the CPG data.
<br />
13. Now install the vulnerability scanner by downloading the repository zip from github and extracting the zip:<br />
    •	wget https://github.com/AndCplusplus/cpg_evaluation-SE/archive/main.zip

<br /><br /><br /><br /><br /><br />
<a name="usage"></a>Usage:<br />
After installing prerequisites and downloading this repository use the terminal to run the teamten.py

In a terminal window run teamten.py:
python3 teamten.py 
<img width="975" height="247" alt="image" src="https://github.com/user-attachments/assets/53be24ef-0891-4a75-8a90-afe1282d6566" />


Once the gui opens press the “Upload File” button and select a .c file to upload:
<img width="834" height="809" alt="image" src="https://github.com/user-attachments/assets/4b44d76c-c863-4def-bbe9-0b971e14c10a" />

 
When the file is uploaded the status bar will display the current file.  After your file is loaded press the “Scan for Vulnerabilities” button to begin scan.
<img width="975" height="230" alt="image" src="https://github.com/user-attachments/assets/db9ded2e-7f57-42ce-972e-c2d8205646f1" />

 
After the file is scanned the first time a CFG graph showing the vulnerabilities is displayed and the table below the graph will show where the vulnerabilities are located along with the type and severity of the vulnerabilities.
<img width="975" height="950" alt="image" src="https://github.com/user-attachments/assets/383637aa-c1f3-4f1c-9bf4-441738746d4d" />

You can then select another type of graph to be displayed for the current file or upload a new file.
<img width="464" height="239" alt="image" src="https://github.com/user-attachments/assets/f5bea8b5-4414-427d-9b3f-8e83b2497a8f" />
<img width="434" height="231" alt="image" src="https://github.com/user-attachments/assets/76bc73a6-c833-456a-874d-c2394914a108" />

  

Here is a closer look at the table:  
<img width="975" height="100" alt="image" src="https://github.com/user-attachments/assets/0e93b168-48e1-4153-94b7-50c9b0aaa15c" />







<a name="demo"></a>Demo:<br />
[![Scanner Demo](https://i9.ytimg.com/vi_webp/uKoejHmPt8Y/mq1.webp?sqp=CKDFuMkG-oaymwEmCMACELQB8quKqQMa8AEB-AH-CYAC0AWKAgwIABABGHIgRSgmMA8=&rs=AOn4CLDtpET5GecYZqztGKV10IeRAmXPPw)](https://youtu.be/uKoejHmPt8Y)



