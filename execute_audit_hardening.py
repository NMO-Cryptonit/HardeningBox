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

        
    def do_Hardening(self, args): # Call fonction when user write 'hardening'
        self.ScriptDirectory()
        self.Hardening()

    def do_Audit(self, args): # Call fonction when user write 'audit'
        self.ScriptDirectory()
        self.Audit()

    # Execution of command with the error output
    def ExecuteCommand(self, command):
        try:
            result = subprocess.Popen(["sudo", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate(timeout=5)
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            result.kill()
            return -1, "", ""  # Return Code -1

    # Execution of script with the error output
    def ExecuteScript(self, script):
        try:
            result = subprocess.Popen(["sudo",script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate(timeout=5)
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            result.kill()
            return -1, "", ""  # Return Code -1

   
        
    def ScriptDirectory(self): # Fonction that transfer the CSV with all commands and scripts in files 
        # Load the existing CSV file
        input_csv_path = input("Specify the name of the input CSV file : ")
        output_csv_path = ("organize.csv")


        df = pd.read_csv(input_csv_path)

        # Create a new DataFrame with the columns
        columns = ['audit_command', 'audit_script', 'hardening_command', 'hardening_script', 'Policy_Name', 'Audit_output']
        result_df = pd.DataFrame(columns=columns)

        # Create directory
        script_directory = 'scripts'
        os.makedirs(script_directory, exist_ok=True)

        # Process each row
        print("Loading...")
        for index, row in df.iterrows():
            # Audit command
        
            script1_content = row['Audit_command']
            script1_filename = f"{script_directory}/{row['ID']}_audit_command.sh"
            if pd.notna(script1_content):
                pd.Series([script1_content], name='audit_command').to_csv(script1_filename, index=False, header=False)
                row['audit_command'] = script1_filename
            else:
                row['audit_command'] = ''

            # Audit script

            script2_content = row['Audit_script']
            script2_filename = f"{script_directory}/{row['ID']}_audit_script.sh"
            if pd.notna(script2_content):
                pd.Series([script2_content], name='audit_script').to_csv(script2_filename, index=False, header=False)
                row['audit_script'] = script2_filename

            
            else:
                row['audit_script'] = ''
        
            # Hardening command
            script3_content = row['Hardening_command']
            script3_filename = f"{script_directory}/{row['ID']}_Hardening_command.sh"
            if pd.notna(script3_content):
                pd.Series([script3_content], name='hardening_command').to_csv(script3_filename, index=False, header=False)
                row['hardening_command'] = script3_filename
            else:
                row['hardening_command'] = ''

            # Hardening script
            script4_content = row['Hardening_script']
            script4_filename = f"{script_directory}/{row['ID']}_Hardening_script.sh"
            if pd.notna(script4_content):
                pd.Series([script4_content], name='hardening_script').to_csv(script4_filename, index=False, header=False)
                row['hardening_script'] = script4_filename
            else:
                row['hardening_script'] = ''

            # Policy Name
            script5_content = row['Policy_Name']
            script5_filename = f"{row['Policy_Name']}"
            if pd.notna(script5_content):
                row['Policy_Name'] = script5_filename
            else:
                row['Policy_Name'] = ''

            #output commands
            script6_content = row['Audit_output']
            script6_filename = f"{row['Audit_output']}"
            if pd.notna(script6_content):
                row['Audit_output'] = script6_filename
            else:
                row['Audit_output'] = ''

            # Append the processed row to the result DataFrame
            result_df = result_df._append(row[columns])
        
        # Save the result DataFrame to the output CSV
        result_df.to_csv(output_csv_path, index=False)
    
        print("\norganize.csv is created\nFinish !")






    def Audit(self): # execute audit for commands and scripts and conditions for some politics

        csv_file = ("organize.csv")
        df = pd.read_csv(csv_file)
        logs_directory = 'logs'
        os.makedirs(logs_directory, exist_ok=True)
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_audit.txt')
        abs_file_path = os.path.join(cur_path, new_path)
        f = open(abs_file_path, 'r+')
        f.truncate(0)
        print("Execution of organize.csv")

        for index, columns in df.iterrows():

            command = columns['audit_command']
            script = columns['audit_script']
            policy_name = columns['Policy_Name']
            command_output = columns['Audit_output']

            if pd.notna(command):

                subprocess.run(["chmod", "770", command], check = True)

                with open(command, 'r') as file:
                    command_replace = file.read()
                command_replace = command_replace.replace('`','"')
                with open(command, 'w') as file:
                    file.write(command_replace)

                returncode, stdout, stderr = self.ExecuteCommand(command)

                with open(abs_file_path, 'a') as f:
                    stdout = re.sub(r'\s+', ' ', str(stdout)).strip()
                    command_output = re.sub(r'\s+', ' ', str(command_output)).strip()


                    f.write("\nPolicy Name: "+ str(policy_name) +"\n"+command+"\n") 
                    if str(stderr) == "" and str(returncode) == "1": # des commandes s'exécute bien mais return aucun résultat donc le returncode renvoie 1 comme erreur donc on contourne ce problème
                        f.write("Return Code : 0" + "\n Command Error : "+ stderr)
                    elif "No such file or directory" in str(stderr): #execute bien la commande renvoi un return code error donc on  met une condition 
                        f.write("Return Code : 0" + "\n Command Error : "+ stderr)
                    elif "is not installed" in str(policy_name) and "no packages found matching" in str(stderr): # verify that the packages is not installed
                        f.write("Return Code : 0" + "\n Command Error : "+ stderr)
                    else:

                        f.write("Return Code : "+str(returncode) + "\n") 
                        f.write("Command Error : "+ str(stderr) )
                        f.write("Command Output : "+str(stdout) + "\n")



                    if str(command_output) != 'nan' and str(stdout) !="" and str(stdout) in str(command_output).strip():
                        f.write("Audit Result: PASS\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    elif "not installed" in str(policy_name) or "is removed" and "no packages found matching" in str(stderr): #verify that the packages is not installed
                        f.write("Audit Result: PASS\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    elif ("not enabled" in str(command_output) and "no such file or directory" in str(stderr)) or "disabled" in str(stderr):
                        f.write("Audit Result: PASS\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    elif "is installed" in str(policy_name) and "ok installed" in str(stdout):
                        f.write("Audit Result: PASS\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    elif "is enabled" in str(command_output) and "No such file or directory" in str(stderr):
                        f.write("Audit Result: FAIL\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    elif "is uninstalled" in str(policy_name) and "is not installed" in str(stderr) or "not-installed" in str(stdout):
                        f.write("Audit Result: PASS\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                    else:
                        f.write("Audit Result: FAIL\n")
                        f.write("RETURN :" + str(command_output) + "\n")
                        f.write("\n")
                        f.write("\n")
                        
                print(f"\nPolicy Name: {policy_name} {command}")              


            if pd.notna(script):

                subprocess.run(["chmod",  "770", script], check = True)

                with open(script, 'r') as file:
                    script_replace = file.read()
                script_replace = script_replace.replace('`','"')
                script_replace = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', script_replace, flags=re.DOTALL)
                script_replace = re.sub(r'}"$', '}', script_replace)
                with open(script, 'w') as file:
                    file.write(script_replace)

                returncode, stdout, stderr = self.ExecuteScript(script)

                with open(abs_file_path, 'a') as f:
                   f.write("Policy Name: "+ str(policy_name) +"\n")
                   f.write(script+"\n"+"Return Code : "+str(returncode)+"\n"+"Command Output : "+str(stdout)+"\n"+"Command Error : "+ str(stderr) + "\n" )

                print(f"Policy Name: {policy_name} {script}")

        self.ResultAudit()

 # Execute hardening command and script

    def Hardening(self):
        csv_file = ("organize.csv")
        df = pd.read_csv(csv_file)
        logs_directory = 'logs'
        os.makedirs(logs_directory, exist_ok=True)
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_hardening.txt')
        abs_file_path = os.path.join(cur_path, new_path)
        f = open(abs_file_path, 'r+')
        f.truncate(0)
        print("Execution of organize.csv")

        for index, columns in df.iterrows():

            command = columns['hardening_command']
            script = columns['hardening_script']
            policy_name = columns['Policy_Name']


            if pd.notna(command):

                subprocess.run(["chmod", "770", command], check = True)

                with open(command, 'r') as file:
                    command_replace = file.read()
                command_replace = command_replace.replace('`','"')
                with open(command, 'w') as file:
                    file.write(command_replace)
                returncode, stdout, stderr = self.ExecuteCommand(command)
                with open(abs_file_path, 'a') as f:
                    stdout = re.sub(r'\s+', ' ', str(stdout)).strip()


                    f.write("\nPolicy Name: "+ str(policy_name) +"\n"+command+"\n") 
                    if str(stderr) == "" and str(returncode) == "1": # des commandes s'exécute bien mais return aucun résultat donc le returncode renvoie 1 comme erreur donc on contourne ce problème
                        f.write("Return Code : 0" + "\n Command Error : "+ str(stderr)+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: PASS\n")
                    elif str(returncode) == '0':
                        f.write("Return Code : 0" + "\n Command Error : "+ stderr+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: PASS\n")
                    else:
                        f.write("Return Code : "+str(returncode) + "\n Command Error : "+ str(stderr)+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: FAIL\n")

                print(f"Policy Name: {policy_name} {command}")


            if pd.notna(script):

                subprocess.run(["chmod",  "770", script], check = True)

                with open(script, 'r') as file:
                    script_replace = file.read()
                script_replace = script_replace.replace('`','"')
                script_replace = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', script_replace, flags=re.DOTALL)
                script_replace = re.sub(r'}"$', '}', script_replace)
                with open(script, 'w') as file:
                    file.write(script_replace)
                returncode, stdout, stderr = self.ExecuteScript(script)
                with open(abs_file_path, 'a') as f:
                    f.write("\nPolicy Name: "+ str(policy_name) +"\n"+script+"\n") 
                    if str(stderr) == "" and str(returncode) == "1": # des commandes s'exécute bien mais return aucun résultat donc le returncode renvoie 1 comme erreur donc on contourne ce problème
                        f.write("Return Code : 0" + "\n Command Error : "+ str(stderr)+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: PASS\n")

                    elif str(returncode) == '0':
                        f.write("Return Code : 0" + "\n Command Error : "+ stderr+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: PASS\n")
                    else:
                        f.write("Return Code : "+str(returncode) + "\n Command Error : "+ str(stderr)+"Command Output : "+str(stdout)+"\n")
                        f.write("Audit Result: FAIL\n")

                print(f"Policy Name: {policy_name} {script}")


        self.ResultHardening()

    def ResultAudit(self):
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_audit.txt')
        abs_file_path = os.path.join(cur_path, new_path)

        script_results = {}
        policy_names = []

        with open(abs_file_path, 'r') as file:
            current_policy_name = None
            current_script_prefix = None
            audit_result = None
            return_code = None

            for line in file:
                if line.startswith("Policy Name: "):
                    current_policy_name = line[len("Policy Name: "):].strip()
                    policy_names.append(current_policy_name)
                elif line.startswith("scripts/") and current_policy_name is not None:
                    current_script_prefix = line.split("_")[0].replace("scripts/", "")
                elif "Return Code :" in line:
                    parts = line.split("Return Code : ")
                    if len(parts) > 1:
                        return_code = parts[1].split()[0].strip()
                elif "FAIL" in line:
                        audit_result = "FAIL"
                elif "PASS" in line:
                        audit_result = "PASS"


                    
                elif line.strip() == "":

                     # If an empty line is encountered, it indicates the end of a section, save the result
                    if current_policy_name is not None and current_script_prefix is not None:
                        combined_name = f"{current_script_prefix} : {current_policy_name}"
                        script_results[combined_name] = f" -> {audit_result}({return_code})"
                    current_policy_name = None
                    current_script_prefix = None
                    audit_result = "FAIL" # if empty line is encountered, there is a command error so its automatically FAIL 
                    return_code = None

        # Write results to a log file
        with open('retoura.log', 'w') as log_file:
            for name, result in script_results.items():
                log_file.write(f"{name} {result}\n")

        print("Log file 'retour.log' created successfully.")
            

    def ResultHardening(self):
        cur_path = os.path.dirname(__file__)
        new_path = os.path.relpath('logs/log_hardening.txt')
        abs_file_path = os.path.join(cur_path, new_path)

        script_results = {}
        policy_names = []

        with open(abs_file_path, 'r') as file:
            current_policy_name = None
            current_script_prefix = None
            audit_result = None
            return_code = None

            for line in file:
                if line.startswith("Policy Name: "):
                    current_policy_name = line[len("Policy Name: "):].strip()
                    policy_names.append(current_policy_name)
                elif line.startswith("scripts/") and current_policy_name is not None:
                    current_script_prefix = line.split("_")[0].replace("scripts/", "")
                elif "Return Code : " in line:
                    parts = line.split("Return Code : ")
                    if len(parts) > 1:
                        return_code = parts[1].split()[0].strip()
                elif "FAIL" in line:
                        audit_result = "FAIL"
                elif "PASS" in line:
                        audit_result = "PASS"


                    
                elif line.strip() == "":

                     # If an empty line is encountered, it indicates the end of a section, save the result
                    if current_policy_name is not None and current_script_prefix is not None:
                        combined_name = f"{current_script_prefix} : {current_policy_name}"
                        script_results[combined_name] = f" -> {audit_result}({return_code})"
                    current_policy_name = None
                    current_script_prefix = None
                    audit_result = "FAIL" # if empty line is encountered, there is a command error so its automatically FAIL 
                    return_code = None

        # Write results to a log file
        with open('retourh.log', 'w') as log_file:
            for name, result in script_results.items():
                log_file.write(f"{name} {result}\n")

        print("Log file 'retour.log' created successfully.")


if __name__ == '__main__':
    shell().cmdloop()