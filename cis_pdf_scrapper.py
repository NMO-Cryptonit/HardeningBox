import re
from Errors import throw

class CISPdfScrapper:
    
    def __init__(self, pdf2txt, output_filepath):
        self.pdf2txt = pdf2txt
        self.output_filepath = output_filepath

    """
        This function will cut the txt to retrieve the policies only.
    """
    def LimitTxtToPoliciesOnly(self):
        recommendation_cut = self.pdf2txt.split('\nRecommendations\n')[1] # keep everything after Recommendations
        appendix_cut = recommendation_cut.split('\nAppendix: Summary Table\n')[0] # keep everything before Appendix
        self.pdf2txt = appendix_cut


    """
        This function will get the policy level from its name
    """
    def ParsePolicyName(self, policy_name):
        # Get level 
        final_level = ""
        possible_levels = ['(L1)','(L2)','(NG)', '(BL)']
        for level in possible_levels:
            if level in policy_name:
                final_level = level
        return final_level

    """
        This function will identify the order of the different paragraphs.
    """
    def setParagraphsOrder(self, policy):
        dict_index = {}

        hardeningcommands=False
        if 'Remediation:' in policy:
            dict_index['Remediation:'] = policy.find('Remediation:')
            hardeningcommands=True

        hardeningscripts=False
        if 'Remediation:' in policy:
            dict_index['Remediation:'] = policy.find('Remediation:')
            hardeningscripts=True

        auditscommands=False
        if 'Audit:' in policy:
            dict_index['Audit:'] = policy.find('Audit:')
            auditscommands=True

        auditsscript=False
        if 'Audit:' in policy:
            dict_index['Audit:'] = policy.find('Audit:')
            auditsscript=True

        auditsoutput=False
        if 'Audit:' in policy:
            dict_index['Audit:'] = policy.find('Audit:')
            auditsoutput=True

        level1=False
        if 'Profile Applicability:' in policy:
            dict_index['Profile Applicability:'] = policy.find('Profile Applicability:')
            level1=True

        description=False
        if 'Description:' in policy:
            dict_index['Description:'] = policy.find('Description:')
            description=True

        rationale=False
        if 'Rationale:' in policy:
            dict_index['Rationale:'] = policy.find('Rationale:')
            rationale=True


        impact=False
        if 'Impact:' in policy:
            dict_index['Impact:'] = policy.find('Impact:')
            impact=True

        audit=False
        if 'Audit:' in policy:
            dict_index['Audit:'] = policy.find('Audit:')
            audit=True

        remediation=False
        if 'Remediation:' in policy:
            dict_index['Remediation:'] = policy.find('Remediation:')
            remediation=True

        defaultvalue=False
        if 'Default Value:' in policy:
            dict_index['Default Value:'] = policy.find('Default Value:')
            defaultvalue=True

        sorted_ = list({k: v for k, v in sorted(dict_index.items(), key=lambda item: item[1])})

        return sorted_, level1, description, rationale, impact, audit, auditscommands, auditsscript, auditsoutput, remediation, hardeningcommands, hardeningscripts, defaultvalue


    """ 
        This function will fetch a txt file containing a CIS Benchmark PDF
        content, to retreive any information about policies (Default Value,
        Recommended Value, Impact, Description, Rationale). It also will
        transform the output to a CSV file.
    """
    def ScrapPdfData(self):
        self.LimitTxtToPoliciesOnly()
        # Transform text into a list of policies, split is based on title : "1.1.1 (L1)" with a regex
        cis_policies = re.split(r"(\d+\.\d+\.\d+.*?)(?=Profile Applicability|$)", self.pdf2txt, flags=re.DOTALL)
        cis_policies.pop(0)
        cis_policies = [''.join(cis_policies[i:i+2]) for i in range(0, len(cis_policies), 2)]


        # Add csv header to csv output
        try:
            f = open(self.output_filepath, 'w+')
            f.write('"ID","Level","Policy_Name","Default Value","Recommended Value","Impact","Description","Rationale","Audit","Audit_command","Audit_script","Audit_output","Hardening","Hardening_command","Hardening_script"\n')
            f.close()
        except:
            throw("Couldn't write to output filepath, please verify you have rights to write, exiting.", "highs")

        for policy in cis_policies:
            print()
            policy = re.sub(r'\d* \| P a g e', '', policy)  # Supprimer les chaînes de page

            # Retrouver l'id de la politique
            id_match = re.match(r'^(\d+[\.\d]+) ', policy)
            if id_match:
                id = id_match.group(1)
                policy_name_match = re.match(id + r' (.*)', policy)
                if policy_name_match:
                    policy_name = policy_name_match.group(1)
                    print(f"ID: {id}, Policy Name: {policy_name}")

            sorted_,level1, description, rationale, impact, audit, auditscommands, auditsscript, auditsoutput, remediation, hardeningcommands, hardeningscripts, defaultvalue = self.setParagraphsOrder(policy)
            
            
            if level1:
                level_index = sorted_.index('Profile Applicability:')
                if level_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[level_index+1]
                level_content = re.findall(r'Profile Applicability:\n((.|\n)*?)'+next_val, policy)

                if len(level_content) > 0:
                    level_content = level_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive level
                else:
                    level_content = ''
            else:
                level_content = ''


            if description:
                description_index = sorted_.index('Description:')
                if description_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[description_index+1]

                description_content = re.findall(r'Description:\n((.|\n)*?)'+next_val, policy)
                if len(description_content) > 0:
                    description_content = description_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive description
                else:
                    description_content = ''
                
                recommended_value = re.findall(r'(?<=The recommended state for this setting is).*?(?=\.)', description_content) # Windows recommended value
                if len(recommended_value) == 0:
                    recommended_value = re.findall(r'(?=It is recommended).*?(?=\.)', description_content) # IIS recommended value
                if len(recommended_value) != 0:
                    recommended_value = recommended_value[0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode()
                else:
                    recommended_value = ""
            else:
                description_content = ''
                recommended_value = ''


            if rationale:
                rationale_index = sorted_.index('Rationale:')
                if rationale_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[rationale_index+1]
                rationale_content = re.findall(r'Rationale:\n((.|\n)*?)'+next_val, policy)

                if len(rationale_content) > 0:
                    rationale_content = rationale_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive rationale
                else:
                    rationale_content = ''
            else:
                rationale_content = ''


            if audit:
                audit_index = sorted_.index('Audit:')
                if audit_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[audit_index+1]

                audit_content = re.findall(r'Audit:\n((.|\n)*?)'+next_val, policy)
                if len(audit_content) > 0:
                    audit_contentv1 = audit_content[0][0].replace('\n','zzz').replace("\"","`").encode("ascii", "ignore").decode()
                    audit_contentv2 = audit_content[0][0].replace('\n','xxx').replace("\"","`").encode("ascii", "ignore").decode()
                    audit_content = audit_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive description
                else:
                    audit_content = ''
            else:
                audit_content = ''


            if auditsoutput:
                audito_index = sorted_.index('Audit:')
                if audito_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[audito_index+1]

                audit_output = re.findall(r'enabled', audit_content) # retreive audit output "is enabled"
                if len(audit_output) == 0:
                    audit_output = re.findall(r'verify that the\s+(\w+)', audit_content) # find the next word after the phrase for " nosuid / nodev / chrony its the current pattern"
                if len(audit_output) != 0:
                    audit_output = audit_output[0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode()
                    audit_output = re.sub('^.*?# ', '', audit_output)
                    audit_output = re.sub(r'zzz.*', '', audit_output)

                else:
                    audit_output = ""
            else:
                audit_output = ''
            



            if auditscommands:
                auditc_index = sorted_.index('Audit:')
                if auditc_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[auditc_index+1]

                audit_command = re.findall(r'Run the following command(.*)', audit_contentv1) # retreive audit script
                if len(audit_command) == 0:
                    audit_command = re.findall(r'the following command(.*)', audit_contentv1) # same
                if len(audit_command) != 0:
                    audit_command = audit_command[0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode()
                    audit_command = re.sub('^.*?# ', '', audit_command)
                    audit_command = re.sub(r'zzz.*', '', audit_command)

                else:
                    audit_command = ""
            else:
                audit_command = ''


            if auditsscript:
                audits_index = sorted_.index('Audit:')
                if audits_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[audits_index+1]

                audit_script = re.findall(r'Run the following script(.*\s*})', audit_contentv2) # retreive audit script
                if len(audit_script) == 0:
                    audit_script = re.findall(r'the following script(.*\s*})', audit_contentv2) # same
                if len(audit_script) != 0:
                    audit_script = audit_script[0].replace('xxx','\n').replace("\"","`").encode("ascii", "ignore").decode()
                    audit_script = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', audit_script, flags=re.DOTALL)
                else:
                    audit_script = ""
            else:
                audit_script = ''


            if remediation:
                remediation_index = sorted_.index('Remediation:')
                if remediation_index >= len(sorted_)-1:
                    next_val = 'MITRE ATT&CK Mappings:'
                else:
                    next_val = sorted_[remediation_index+1]
                remediation_content = re.findall(r'Remediation:\n((.|\n)*?)'+next_val, policy)

                remediation_content = re.findall(r'Remediation:\n((.|\n)*?)'+next_val, policy)
                if len(remediation_content) > 0:
                    remediation_contentv1 = remediation_content[0][0].replace('\n','zzz').replace("\"","`").encode("ascii", "ignore").decode()
                    remediation_contentv2 = remediation_content[0][0].replace('\n','xxx').replace("\"","`").encode("ascii", "ignore").decode()
                    remediation_content = remediation_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive description

                else:
                    remediation_content = ''
            else:
                remediation_content = ''
            

            if hardeningcommands:
                remediation_index = sorted_.index('Remediation:')
                if remediation_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[remediation_index+1]

                hardeningcommands = re.findall(r'Run the following command(.*)', remediation_contentv1) # retreive hardening command
                if len(hardeningcommands) == 0:
                    hardeningcommands = re.findall(r'the following command(.*)', remediation_contentv1) # same
                if len(hardeningcommands) != 0:
                    hardeningcommands = hardeningcommands[0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode()
                    hardeningcommands = re.sub('^.*?# ', '', hardeningcommands)
                    hardeningcommands = re.sub(r'zzz.*', '', hardeningcommands)
                else:
                    hardeningcommands = ""
            else:
                hardeningcommands = ''


            if hardeningscripts:
                remediation_index = sorted_.index('Remediation:')
                if remediation_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[remediation_index+1]

                hardeningscripts = re.findall(r'Run the following script(.*\s*})', remediation_contentv2) # retreive hardening script
                if len(hardeningscripts) == 0:
                    hardeningscripts = re.findall(r'The following script(.*\s*})', remediation_contentv2) # same
                if len(hardeningscripts) != 0:
                    hardeningscripts = hardeningscripts[0].replace('xxx','\n').replace("\"","`").encode("ascii", "ignore").decode()
                    hardeningscripts = re.sub(r'.*?\s*#!/usr/bin/env', '#!/usr/bin/env', hardeningscripts, flags=re.DOTALL)
                else:
                    hardeningscripts = ""
            else:
                hardeningscripts = ''


            if impact:
                impact_index = sorted_.index('Impact:')
                if impact_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[impact_index+1]

                impact_content = re.findall(r'Impact:\n((.|\n)*?)'+next_val, policy)
                if len(impact_content) > 0:
                    impact_content = impact_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive impact
                else:
                    impact_content = ''
            else:
                impact_content = ''

            if defaultvalue:
                defaultvalue_index = sorted_.index('Default Value:')
                if defaultvalue_index >= len(sorted_)-1:
                    next_val = r'\n(.*)'
                else:
                    next_val = sorted_[defaultvalue_index+1]
                defaultvalue_content = re.findall(r'Default Value:\n((.|\n)*?)'+next_val, policy)
                if len(defaultvalue_content) > 0:
                    defaultvalue_content = defaultvalue_content[0][0].replace('\n','').replace("\"","`").encode("ascii", "ignore").decode() # Retreive default value
                else:
                    defaultvalue_content = ''
            else:
                defaultvalue_content = ''

            # parse policy name
            level = self.ParsePolicyName(policy_name)

            f = open(self.output_filepath, 'a')
            f.write('"'+id+'","'+level_content+'","'+policy_name+'","'+defaultvalue_content+'","'+recommended_value+'","'+impact_content+'","'+description_content+'","'+rationale_content+'","'+audit_content+'","'+audit_command+'","'+audit_script+'","'+audit_output+'","'+remediation_content+'","'+hardeningcommands+'","'+hardeningscripts+'"\n')
            f.close()