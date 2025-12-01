Document Links: [install](#install) / [usage](#usage)
<img width="1024" height="1024" alt="A graphic-heavy logo" src="https://github.com/user-attachments/assets/57f63bf5-723c-404d-9dbb-34dbb8d74019" />
<center> Vulnerability Scanner<br />
Group project for Software Engineering<br /><br />
</center>


<a name="install">Installation</a>:<br />
Navigate to the directory for the installation and install prerequisites:<br />
•	sudo apt update<br />
•	sudo apt install curl<br />
•	sudo apt install python3<br />
•	sudo apt install python3-tk<br />
•	sudo apt install python3-matplotlib<br />
•	sudo apt install python3-pandas<br />
•	sudo apt install python3-networkx<br />
•	sudo apt install -y openjdk-17-jdk<br />
•	wget https://github.com/joernio/joern/releases/download/v4.0.324/joern-install.sh<br />
•	sudo chmod +x joern-install.sh<br />
•	sudo ./joern-install.sh –interactive=false<br />
•	Extract joern-cli.zip<br />
<br />
Now install the vulnerability scanner by downloading the repository zip from github and extracting the zip:<br />
•	wget https://github.com/AndCplusplus/cpg_evaluation-SE/archive/main.zip

<br />
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



