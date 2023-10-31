import subprocess
from cmd import Cmd
import pandas as pd

class shell(Cmd):
    prompt = 'CI>'
    print(""" 


                          _              _ _   
     ___ _ __ _   _ _ __ | |_ ___  _ __ (_) |_ 
    / __| '__| | | | '_ \| __/ _ \| '_ \| | __|
   | (__| |  | |_| | |_) | || (_) | | | | | |_ 
    \___|_|   \__, | .__/ \__\___/|_| |_|_|\__|
              |___/|_|                         

          
          

    """)
    print("Welcome! Type 'help' to list commands \n")

    def do_help(self, args):
        self.Help()


    def Help(self):
        print("""
              

        +-----------+-------------------------------------------+
        | Commands  | Description                               |
        +-----------+-------------------------------------------+
        | Audit     | Run an Audit on your machine (only Linux) | 
        | Hardening | Harden your machine (only Linux)          |
        +-----------+-------------------------------------------+  
            
              
              """)



    def do_hardening(self, args):
        self.Hardening()

    def do_audit(self, args):
        self.Audit()
    
    def ExecuteCommand(self, command):
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = result.communicate()
        return result.returncode, stdout, stderr
    
    def ExecuteSript(self, script):
        result = subprocess.Popen(script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = result.communicate()
        return result.returncode, stdout, stderr
    
    def Audit(self):
        csv_file = input("Specify the name of the input CSV file : ")
        df = pd.read_csv(csv_file)
        for index, columns in df.iterrows():
            command = columns['audit_command']
            script = columns['audit_script']
            print(f"columns 0 : {command} , columns 1 = {script}")
            if command:
                subprocess.run(["chmod", "770", command], check = True)
                returncode, stdout, stderr = self.ExecuteCommand(command)
                print(command)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")
            if script:
                print(f"columns 0 : {command} , columns 1 = {script}")
                subprocess.run(["chmod",  "770", script], check = True)
                returncode, stdout, stderr = self.ExecuteSript(script)
                print(script)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")

    #
    def Hardening(self):
        csv_file = input("Specify the name of the input CSV file : ")
        df = pd.read_csv(csv_file)
        for index, columns in df.iterrows():
            command = columns['hardening_command']
            script = columns['hardening_script']
            print(f"columns 2 : {command}, columns 3 = {script}")
            if pd.notna(command):
                subprocess.run(["chmod", "770", command], check = True)
                returncode, stdout, stderr = self.ExecuteCommand(command)
                print(command)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")
            if script:
                subprocess.run(["chmod",  "770", script], check = True)
                returncode, stdout, stderr = self.ExecuteSript(script)
                print(script)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")



if __name__ == '__main__':
    shell().cmdloop()

