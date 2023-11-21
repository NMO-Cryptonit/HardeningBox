import subprocess
from cmd import Cmd
import pandas as pd
import re
import os

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

    # Execution of command with the error output
    def ExecuteCommand(self, command):
        try:
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate(timeout=5)
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            print(f"La commande a dépassé le temps imparti. Ignorer et passer à la suivante.")
            result.kill()
            return -1, "", ""  # Code de retour pour indiquer que la commande a été ignorée

    # Execution of script with the error output
    def ExecuteScript(self, script):
        try:
            result = subprocess.Popen(script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate(timeout=5)
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            print(f"La commande a dépassé le temps imparti. Ignorer et passer à la suivante.")
            result.kill()
            return -1, "", ""  # Code de retour pour indiquer que la commande a été ignorée

    # Execute audit command and script

    def Audit(self):

        csv_file = input("Specify the name of the input CSV file : ")
        df = pd.read_csv(csv_file)
        logs_directory = 'logs'
        os.makedirs(logs_directory, exist_ok=True)
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_audit.txt')
        abs_file_path = os.path.join(cur_path, new_path)
        f = open(abs_file_path, 'r+')
        f.truncate(0)

        for index, columns in df.iterrows():

            command = columns['audit_command']
            script = columns['audit_script']
            print(f"columns 0 : {command} , columns 1 = {script}")

            if pd.notna(command):

                subprocess.run(["chmod", "770", command], check = True)
                print("chmod OK")

                with open(command, 'r') as file:
                    command_replace = file.read()
                command_replace = command_replace.replace('`','"')
                with open(command, 'w') as file:
                    file.write(command_replace)

                returncode, stdout, stderr = self.ExecuteCommand(command)

                with open(abs_file_path, 'a') as f:
                    f.write(command+"\n"+"Return Code : "+str(returncode)+"\n"+"Command Output : "+str(stdout)+"\n"+"Command Error : "+ str(stderr) )
                print(command)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")

            if pd.notna(script):

                subprocess.run(["chmod",  "770", script], check = True)
                print("chmod OK")

                with open(script, 'r') as file:
                    script_replace = file.read()
                script_replace = script_replace.replace('`','"')
                script_replace = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', script_replace, flags=re.DOTALL)
                script_replace = re.sub(r'}"$', '}', script_replace)
                with open(script, 'w') as file:
                    file.write(script_replace)

                returncode, stdout, stderr = self.ExecuteScript(script)

                with open(abs_file_path, 'a') as f:
                    f.write(script+"\n"+"Return Code : "+str(returncode)+"\n"+"Command Output : "+str(stdout)+"\n"+"Command Error : "+ str(stderr) )
                print(script)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")
        self.ResultAudit()

 # Execute hardening command and script

    def Hardening(self):
        csv_file = input("Specify the name of the input CSV file : ")
        df = pd.read_csv(csv_file)
        logs_directory = 'logs'
        os.makedirs(logs_directory, exist_ok=True)
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_hardening.txt')
        abs_file_path = os.path.join(cur_path, new_path)
        f = open(abs_file_path, 'r+')
        f.truncate(0)

        for index, columns in df.iterrows():

            command = columns['hardening_command']
            script = columns['hardening_script']
            print(f"columns 2 : {command}, columns 3 = {script}")


            if pd.notna(command):

                subprocess.run(["chmod", "770", command], check = True)
                print("chmod OK")

                with open(command, 'r') as file:
                    command_replace = file.read()
                command_replace = command_replace.replace('`','"')
                with open(command, 'w') as file:
                    file.write(command_replace)
                returncode, stdout, stderr = self.ExecuteCommand(command)
                with open(abs_file_path, 'a') as f:
                    f.write(command+"\n"+"Return Code : "+str(returncode)+"\n"+"Command Output : "+str(stdout)+"\n"+"Command Error : "+ str(stderr) )
                print(command)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")

            if pd.notna(script):

                subprocess.run(["chmod",  "770", script], check = True)
                print("chmod OK")

                with open(script, 'r') as file:
                    script_replace = file.read()
                script_replace = script_replace.replace('`','"')
                script_replace = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', script_replace, flags=re.DOTALL)
                script_replace = re.sub(r'}"$', '}', script_replace)
                with open(script, 'w') as file:
                    file.write(script_replace)
                returncode, stdout, stderr = self.ExecuteScript(script)
                with open(abs_file_path, 'a') as f:
                    f.write(script+"\n"+"Return Code : "+str(returncode)+"\n"+"Command Output : "+str(stdout)+"\n"+"Command Error : "+ str(stderr) )

                print(script)
                print(f"Return Code : {returncode}")
                print(f"Command Output: {stdout}")
                print(f"Command Error: {stderr}")
        self.ResultHardening()

    def ResultAudit(self):
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_audit.txt')
        abs_file_path = os.path.join(cur_path, new_path)

        code_search = ["Return Code : -1", "Return Code : 0", "Return Code : 1", "Return Code : 2", "Return Code : 3","Return Code : 4","Return Code : 126", "Return Code : 127", "Return Code : 128", "Return Code : 255", "FAIL", "SUCCESS"]

        occurences = {texte: 0 for texte in code_search}

        with open(abs_file_path,'r') as file:
            for line in file:
                for texte in code_search:
                    if texte in line:
                        occurences[texte] += 1
        for texte, count in occurences.items():
            print(f"Ocurrences de {texte}: {count}")

    def ResultHardening(self):
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_hardening.txt')
        abs_file_path = os.path.join(cur_path, new_path)

        code_search = ["Return Code : -1", "Return Code : 0", "Return Code : 1", "Return Code : 2", "Return Code : 3","Return Code : 4","Return Code : 32","Return Code : 126", "Return Code : 127", "Return Code : 128", "Return Code : 255", "FAIL"]

        occurences = {texte: 0 for texte in code_search}

        with open(abs_file_path,'r') as file:
            for line in file:
                for texte in code_search:
                    if texte in line:
                        occurences[texte] += 1
        for texte, count in occurences.items():
            print(f"{texte}: {count}")


if __name__ == '__main__':
    shell().cmdloop()