import os
import pandas as pd


print(""" 


                          _              _ _   
     ___ _ __ _   _ _ __ | |_ ___  _ __ (_) |_ 
    / __| '__| | | | '_ \| __/ _ \| '_ \| | __|
   | (__| |  | |_| | |_) | || (_) | | | | | |_ 
    \___|_|   \__, | .__/ \__\___/|_| |_|_|\__|
              |___/|_|                         

          
          

    """)


input_csv_path = input("Specify the name of the input CSV file : ")
output_csv_path = input("Specify the name of the output CSV file : ")

if input_csv_path.endswith(".csv"):
    print("")
else:
    input_csv_path = f"{input_csv_path}.csv"
    print(input_csv_path)

if output_csv_path.endswith(".csv"):
    print("")
else:
    output_csv_path = f"{output_csv_path}.csv"


def ScriptDirectory(input_csv, output_csv):
    # Load the existing CSV file
    df = pd.read_csv(input_csv)

    # Create a new DataFrame with the columns
    columns = ['audit_command', 'audit_script', 'hardening_command', 'hardening_script']
    result_df = pd.DataFrame(columns=columns)

    # Create directory
    script_directory = 'scripts'
    os.makedirs(script_directory, exist_ok=True)

    # Process each row
    for index, row in df.iterrows():
        # Audit command
        script1_content = row['Audit_command']
        if pd.notna(script1_content):
            script1_filename = f"{script_directory}/{row['ID']}_audit_command.sh"
            with open(script1_filename, 'w') as script_file:
                script_file.write(script1_content)
            row['audit_command'] = script1_filename
        else:
            row['audit_command'] = ''

        # Audit script
        script2_content = row['Audit_script']
        if pd.notna(script2_content):
            script2_filename = f"{script_directory}/{row['ID']}_audit_script.sh"
            with open(script2_filename, 'w') as script_file:
                script_file.write(script2_content)
            row['audit_script'] = script2_filename
        else:
            row['audit_script'] = ''

        # Hardening command
        script3_content = row['Hardening_command']
        if pd.notna(script3_content):
            script3_filename = f"{script_directory}/{row['ID']}_Hardening_command.sh"
            with open(script3_filename, 'w') as script_file:
                script_file.write(script3_content)
            row['hardening_command'] = script3_filename
        else:
            row['hardening_command'] = ''

        # Hardening script
        script4_content = row['Hardening_script']
        if pd.notna(script4_content):
            script4_filename = f"{script_directory}/{row['ID']}_Hardening_script.sh"
            with open(script4_filename, 'w') as script_file:
                script_file.write(script4_content)
            row['hardening_script'] = script4_filename
        else:
            row['hardening_script'] = ''

        # Append the processed row to the result DataFrame
        result_df = result_df._append(row[columns])

    # Save the result DataFrame to the output CSV
    result_df.to_csv(output_csv, index=False)

# Call the function
ScriptDirectory(input_csv_path, output_csv_path)


