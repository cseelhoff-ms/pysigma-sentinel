from sigma.collection import SigmaCollection
from sigma.backends.azure import AzureBackend
from sigma.pipelines.azure import azure_windows_pipeline
from sigma.rule import SigmaRule
#from datetime import date
from sigma.rule import SigmaRuleTag
import json
import re

with open('template.json', 'r') as f:
    templateContents = f.read()

backend: AzureBackend = AzureBackend(processing_pipeline=azure_windows_pipeline())
procCollection: SigmaCollection = SigmaCollection.load_ruleset(['./process_creation'])
sigmaRules: 'list[SigmaRule]' = procCollection.rules
#create a hashset for unique tactics and techniques
tacticSigmaDict: 'dict[str, str]' = {
    'reconnaissance':'Reconnaissance',
    'resource_development':'ResourceDevelopment',
    'initial_access':'InitialAccess',
    'execution':'Execution',
    'persistence':'Persistence',
    'privilege_escalation':'PrivilegeEscalation',
    'defense_evasion':'DefenseEvasion',
    'credential_access':'CredentialAccess',
    'discovery':'Discovery',
    'lateral_movement':'LateralMovement',
    'collection':'Collection',
    'command_and_control':'CommandAndControl',
    'exfiltration':'Exfiltration',
    'impact':'Impact',
    'impair_process_control':'ImpairProcessControl',
    'inhibit_response_function':'InhibitResponseFunction'
}

subTactics: 'dict[str, list[str]]' = {
    'Reconnaissance':["T1595.001", "T1595.002", "T1592.001", "T1592.002", "T1592.003", "T1592.004", "T1589.001", "T1589.002", "T1589.003", "T1590.001", "T1590.002", "T1590.003", "T1590.004", "T1590.005", "T1590.006", "T1591.001", "T1591.002", "T1591.003", "T1591.004", "T1598.001", "T1598.002", "T1598.003", "T1597.001", "T1597.002", "T1596.001", "T1596.002", "T1596.003", "T1596.004", "T1596.005", "T1593.001", "T1593.002"],
    'ResourceDevelopment':["T1583.001", "T1583.002", "T1583.003", "T1583.004", "T1583.005", "T1583.006", "T1586.001", "T1586.002", "T1584.001", "T1584.002", "T1584.003", "T1584.004", "T1584.005", "T1584.006", "T1587.001", "T1587.002", "T1587.003", "T1587.004", "T1585.001", "T1585.002", "T1588.001", "T1588.002", "T1588.003", "T1588.004", "T1588.005", "T1588.006", "T1608.001", "T1608.002", "T1608.003", "T1608.004", "T1608.005"],
    'InitialAccess':["T1566.001", "T1566.002", "T1566.003", "T1195.001", "T1195.002", "T1195.003", "T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    'Execution':["T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008", "T1559.001", "T1559.002", "T1053.001", "T1053.002", "T1053.003", "T1053.004", "T1053.005", "T1053.006", "T1053.007", "T1569.001", "T1569.002", "T1204.001", "T1204.002", "T1204.003"],
    'Persistence':["T1098.001", "T1098.002", "T1098.003", "T1098.004", "T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005", "T1547.006", "T1547.007", "T1547.008", "T1547.009", "T1547.010", "T1547.011", "T1547.012", "T1547.013", "T1547.014", "T1037.001", "T1037.002", "T1037.003", "T1037.004", "T1037.005", "T1136.001", "T1136.002", "T1136.003", "T1543.001", "T1543.002", "T1543.003", "T1543.004", "T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.006", "T1546.007", "T1546.008", "T1546.009", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.014", "T1546.015", "T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012", "T1556.001", "T1556.002", "T1556.003", "T1556.004", "T1137.001", "T1137.002", "T1137.003", "T1137.004", "T1137.005", "T1137.006", "T1542.001", "T1542.002", "T1542.003", "T1542.004", "T1542.005", "T1053.001", "T1053.002", "T1053.003", "T1053.004", "T1053.005", "T1053.006", "T1053.007", "T1505.001", "T1505.002", "T1505.003", "T1205.001", "T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    'PrivilegeEscalation' :["T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005", "T1547.001", "T1547.002", "T1547.003", "T1547.004", "T1547.005", "T1547.006", "T1547.007", "T1547.008", "T1547.009", "T1547.010", "T1547.011", "T1547.012", "T1547.013", "T1547.014", "T1037.001", "T1037.002", "T1037.003", "T1037.004", "T1037.005", "T1543.001", "T1543.002", "T1543.003", "T1543.004", "T1484.001", "T1484.002", "T1546.001", "T1546.002", "T1546.003", "T1546.004", "T1546.005", "T1546.006", "T1546.007", "T1546.008", "T1546.009", "T1546.010", "T1546.011", "T1546.012", "T1546.013", "T1546.014", "T1546.015", "T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012", "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1053.001", "T1053.002", "T1053.003", "T1053.004", "T1053.005", "T1053.006", "T1053.007", "T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    'DefenseEvasion':["T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005", "T1484.001", "T1484.002", "T1480.001", "T1222.001", "T1222.002", "T1564.001", "T1564.002", "T1564.003", "T1564.004", "T1564.005", "T1564.006", "T1564.007", "T1574.001", "T1574.002", "T1574.004", "T1574.005", "T1574.006", "T1574.007", "T1574.008", "T1574.009", "T1574.010", "T1574.011", "T1574.012", "T1562.001", "T1562.002", "T1562.003", "T1562.004", "T1562.006", "T1562.007", "T1562.008", "T1070.001", "T1070.002", "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1036.001", "T1036.002", "T1036.003", "T1036.004", "T1036.005", "T1036.006", "T1556.001", "T1556.002", "T1556.003", "T1556.004", "T1578.001", "T1578.002", "T1578.003", "T1578.004", "T1601.001", "T1601.002", "T1599.001", "T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005", "T1542.001", "T1542.002", "T1542.003", "T1542.004", "T1542.005", "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1218.001", "T1218.002", "T1218.003", "T1218.004", "T1218.005", "T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011", "T1218.012", "T1216.001", "T1553.001", "T1553.002", "T1553.003", "T1553.004", "T1553.005", "T1553.006", "T1205.001", "T1127.001", "T1550.001", "T1550.002", "T1550.003", "T1550.004", "T1078.001", "T1078.002", "T1078.003", "T1078.004", "T1497.001", "T1497.002", "T1497.003", "T1600.001", "T1600.002"],
    'CredentialAccess':["T1110.001", "T1110.002", "T1110.003", "T1110.004", "T1555.001", "T1555.002", "T1555.003", "T1555.004", "T1555.005", "T1606.001", "T1606.002", "T1056.001", "T1056.002", "T1056.003", "T1056.004", "T1557.001", "T1557.002", "T1556.001", "T1556.002", "T1556.003", "T1556.004", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008", "T1558.001", "T1558.002", "T1558.003", "T1558.004", "T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007"],
    'Discovery':["T1087.001", "T1087.002", "T1087.003", "T1087.004", "T1069.001", "T1069.002", "T1069.003", "T1518.001", "T1016.001", "T1497.001", "T1497.002", "T1497.003"],
    'LateralMovement':["T1563.001", "T1563.002", "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006", "T1550.001", "T1550.002", "T1550.003", "T1550.004"],
    'Collection':["T1560.001", "T1560.002", "T1560.003", "T1602.001", "T1602.002", "T1213.001", "T1213.002", "T1074.001", "T1074.002", "T1114.001", "T1114.002", "T1114.003", "T1056.001", "T1056.002", "T1056.003", "T1056.004", "T1557.001", "T1557.002"],
    'CommandAndControl':["T1071.001", "T1071.002", "T1071.003", "T1071.004", "T1132.001", "T1132.002", "T1001.001", "T1001.002", "T1001.003", "T1568.001", "T1568.002", "T1568.003", "T1573.001", "T1573.002", "T1090.001", "T1090.002", "T1090.003", "T1090.004", "T1205.001", "T1102.001", "T1102.002", "T1102.003"],
    'Exfiltration':["T1020.001", "T1048.001", "T1048.002", "T1048.003", "T1011.001", "T1052.001", "T1567.001", "T1567.002"],
    'Impact':["T1565.001", "T1565.002", "T1565.003", "T1491.001", "T1491.002", "T1561.001", "T1561.002", "T1499.001", "T1499.002", "T1499.003", "T1499.004", "T1498.001", "T1498.002"]
}

subTechniquesDict: 'dict[str, str]' = {}
for key in subTactics:
    for tactic in subTactics[key]:
        subTechniquesDict[tactic] = key

mainTactics: 'dict[str, list[str]]' = {
    'Reconnaissance' : ["T1595", "T1592", "T1589", "T1590", "T1591", "T1598", "T1597", "T1596", "T1593", "T1594"],
    'ResourceDevelopment' : ["T1583", "T1586", "T1584", "T1587", "T1585", "T1588", "T1608"],
    'InitialAccess' : ["T1189", "T1190", "T1133", "T1200", "T1566", "T1091", "T1195", "T1199", "T1078"],
    'Execution' : ["T1059", "T1609", "T1610", "T1203", "T1559", "T1106", "T1053", "T1129", "T1072", "T1569", "T1204", "T1047"],
    'Persistence' : ["T1098", "T1197", "T1547", "T1037", "T1176", "T1554", "T1136", "T1543", "T1546", "T1133", "T1574", "T1525", "T1556", "T1137", "T1542", "T1053", "T1505", "T1205", "T1078"],
    'PrivilegeEscalation' : ["T1548", "T1134", "T1547", "T1037", "T1543", "T1484", "T1611", "T1546", "T1068", "T1574", "T1055", "T1053", "T1078"],
    'DefenseEvasion' : ["T1548", "T1134", "T1197", "T1612", "T1622", "T1140", "T1610", "T1006", "T1484", "T1480", "T1211", "T1222", "T1564", "T1574", "T1562", "T1070", "T1202", "T1036", "T1556", "T1578", "T1112", "T1601", "T1599", "T1027", "T1647", "T1542", "T1055", "T1620", "T1207", "T1014", "T1553", "T1218", "T1216", "T1221", "T1205", "T1127", "T1535", "T1550", "T1078", "T1497", "T1600", "T1220"],
    'CredentialAccess' : ["T1557", "T1110", "T1555", "T1212", "T1187", "T1606", "T1056", "T1556", "T1111", "T1621", "T1040", "T1003", "T1528", "T1558", "T1539", "T1552", "T1613", "T1614"],
    'Discovery' : ["T1087", "T1010", "T1217", "T1580", "T1538", "T1526", "T1619", "T1613", "T1622", "T1482", "T1083", "T1615", "T1046", "T1135", "T1040", "T1201", "T1120", "T1069", "T1057", "T1012", "T1018", "T1518", "T1082", "T1614", "T1016", "T1049", "T1033", "T1007", "T1124", "T1497"],
    'LateralMovement' : ["T1210", "T1534", "T1570", "T1563", "T1021", "T1091", "T1072", "T1080", "T1550"],
    'Collection' : ["T1557", "T1560", "T1123", "T1119", "T1185", "T1115", "T1530", "T1602", "T1213", "T1005", "T1039", "T1025", "T1074", "T1114", "T1056", "T1113", "T1125", "T1609", "T1610"],
    'CommandAndControl' : ["T1071", "T1092", "T1132", "T1001", "T1568", "T1573", "T1008", "T1105", "T1104", "T1095", "T1571", "T1572", "T1090", "T1219", "T1205", "T1102"],
    'Exfiltration' : ["T1020", "T1030", "T1048", "T1041", "T1011", "T1052", "T1567", "T1029", "T1537"],
    'Impact' : ["T1531", "T1485", "T1486", "T1565", "T1491", "T1561", "T1499", "T1495", "T1490", "T1498", "T1496", "T1489", "T1529"]
}

mainTechniquesDict: 'dict[str, str]' = {}
for key in mainTactics:
    for tactic in mainTactics[key]:
        mainTechniquesDict[tactic] = key

# Convert all keys to uppercase
tacticSigmaDict = {k.upper(): v for k, v in tacticSigmaDict.items()}

#severityLevelDict: dict[str, str] = {
#    'low': 'low',
#    'medium': 'medium',
#    'high': 'high',
#    'critical': 'high'
#}

severityLevelDict = {
    'low': 'informational',
    'medium': 'low',
    'high': 'medium',
    'critical': 'high'
}

ruleidLevelDict = {
    'low': '0',
    'medium': '1',
    'high': '2',
    'critical': '3'
}

for levelFilter in severityLevelDict.keys():

    combinedTactics: 'set[str]' = set()
    combinedTechniques: 'set[str]' = set()
    combinedQuery: str = ''
    ruleids: 'list[str]' = []

    queryIndex = 0
    fileIndex = 0

    for sigmaRule in sigmaRules:
        level: str = str(sigmaRule.level).lower()
        if level != levelFilter:
            continue
        author: str = sigmaRule.author if sigmaRule.author is not None else ""
        description: str = sigmaRule.description if sigmaRule.description is not None else ""
        falsepositives: 'list[str]' = sigmaRule.falsepositives
        ruleid: str = str(sigmaRule.id)
#        if ruleid == '24e3e58a-646b-4b50-adef-02ef935b9fc8':
#            continue
        #ruleid = ruleid.replace('-', '')
        date_modified: str = str(sigmaRule.modified)
        references: 'list[str]' = sigmaRule.references
        sourceURL: str = str(sigmaRule.source.path)
        status: str = str(sigmaRule.status)
        title: str = sigmaRule.title
        #description += '\nSource URL: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/' + sourceURL
        #description += '\nAuthor: ' + author
        #description += '\nDate Modified: ' + date_modified
        #description += '\nStatus: ' + status
        #description += '\nReferences: ' + ', '.join(references)
        #description += '\nFalse Positives: ' + ', '.join(falsepositives) 
            
        tactics: 'set[str]' = set()
        techniques: 'set[str]' = set()

        sigmaTags: 'list[SigmaRuleTag]' = sigmaRule.tags
        for tag in sigmaTags:
            tagName = tag.name.upper()
            if tagName in tacticSigmaDict:
                tactics.add(tacticSigmaDict[tagName])
            elif (tagName[0] == 'T') and tagName[1:5].isdigit():
                mainTechnique = tagName[:5]
                if tagName in subTechniquesDict:
                    tactics.add(subTechniquesDict[tagName])
                #    techniques.add(tagName)
                if mainTechnique in mainTechniquesDict:
                    tactics.add(mainTechniquesDict[mainTechnique])
                    techniques.add(mainTechnique)
    
        convertedStrings: 'list[str]' = backend.convert_rule(sigmaRule)

        newQuery = convertedStrings[0].replace('Hashes contains "IMPHASH=', 'TargetProcessIMPHASH=~"')
        newQuery = newQuery.replace('Hashes =~ "IMPHASH=', 'TargetProcessIMPHASH=~"')
        newQuery = newQuery.replace('Hashes =~ "MD5=', 'TargetProcessMD5=~"')
        newQuery = newQuery.replace('Hashes =~ "SHA256=', 'TargetProcessSHA256=~"')

        newQuery = newQuery.replace('Hashes =~ "MD5=', 'TargetProcessMD5=~"')
        newQuery = newQuery.replace('Hashes =~ "SHA256=', 'TargetProcessSHA256=~"')

        newQuery = newQuery.replace('Hashes contains "', 'TargetProcessIMPHASH=~"')
        newQuery = newQuery.replace('Hashes =~ "', 'TargetProcessIMPHASH=~"')

        # search for the regex pattern: (?<=[^\\])\\\* and replace with \\\\*
        newQuery = re.sub(r'(?<=[^\\])\\\*', r'\\\\*', newQuery)
        #newQuery = newQuery.replace(':\\*', ':\\\\*') #https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.yml

        newQuery += '|extend RuleId="' + ruleid + '"'
        newQuery += '|extend SourceURL="https://github.com/SigmaHQ/sigma/blob/master/rules/windows/' + sourceURL + '"'
        newQuery += '|extend RuleTitle="' + title + '"'
        newQuery += '|extend RuleDescription=' + json.dumps(description)
        
        queryIndexString: str = 'q' + str(queryIndex)
        query = 'let ' + queryIndexString + '=' + newQuery

        if len(combinedQuery) + len(query) + len('union ' + ', '.join(ruleids) + ';') >= 14000 or sourceURL == 'proc_creation_win_powershell_base64_frombase64string.yml':
            tacticsString = json.dumps(list(combinedTactics))
            techniquesString = json.dumps(list(combinedTechniques))
            combinedQuery += 'union ' + ', '.join(ruleids) + ';'
            combinedQuery = json.dumps(combinedQuery)

            #format str(fileIndex) to 3 digits
            fileIndexString: str = str(fileIndex)
            while len(fileIndexString) < 2:
                fileIndexString = '0' + fileIndexString
            ruleid = '5163A000-5160-5160-5160-5163A0000' + ruleidLevelDict[levelFilter] + fileIndexString
            newTemplate: str = templateContents.replace('---RULEID---', ruleid).replace('---TITLE---', '"Sigma Windows Process Creation ' +  severityLevelDict[levelFilter] + ' ' + fileIndexString + '"').replace('---DESCRIPTION---', '"Sigma Windows Process Creation ' + severityLevelDict[levelFilter] + ' ' + fileIndexString  + '"').replace('---LEVEL---', severityLevelDict[levelFilter]).replace('---QUERY---', combinedQuery).replace('---TACTICS---', tacticsString).replace('---TECHNIQUES---', techniquesString)#.replace('---TAGS---', tagsString)
            #write newTemplate to file
            with open('./output/Sigma Windows Process Creation ' + severityLevelDict[levelFilter] + ' ' + fileIndexString + '.json', 'w') as f:
                f.write(newTemplate)
            fileIndex += 1
            combinedQuery = ''
            ruleids = []
            combinedTactics = set()
            combinedTechniques = set()
            queryIndex = 0

            queryIndexString: str = 'q' + str(queryIndex)
            query = 'let ' + queryIndexString + '=' + newQuery 
            
        combinedQuery += query + ';\n'
        ruleids.append(queryIndexString)
        combinedTactics = combinedTactics.union(tactics)
        combinedTechniques = combinedTechniques.union(techniques)
        #title = json.dumps(title)
        #description = json.dumps(description)
        #query = json.dumps(query)
        #tacticsString = json.dumps(list(tactics))
        #techniquesString = json.dumps(list(techniques))
        queryIndex += 1

    tacticsString = json.dumps(list(combinedTactics))
    techniquesString = json.dumps(list(combinedTechniques))
    combinedQuery += 'union ' + ', '.join(ruleids) + ';'
    combinedQuery = json.dumps(combinedQuery)

    #format str(fileIndex) to 3 digits
    fileIndexString: str = str(fileIndex)
    while len(fileIndexString) < 2:
        fileIndexString = '0' + fileIndexString
    ruleid = '5163A000-5160-5160-5160-5163A0000' + ruleidLevelDict[levelFilter] + fileIndexString
    newTemplate: str = templateContents.replace('---RULEID---', ruleid).replace('---TITLE---', '"Sigma Windows Process Creation ' +  severityLevelDict[levelFilter] + ' ' + fileIndexString + '"').replace('---DESCRIPTION---', '"Sigma Windows Process Creation ' + severityLevelDict[levelFilter] + ' ' + fileIndexString  + '"').replace('---LEVEL---', severityLevelDict[levelFilter]).replace('---QUERY---', combinedQuery).replace('---TACTICS---', tacticsString).replace('---TECHNIQUES---', techniquesString)#.replace('---TAGS---', tagsString)
    #write newTemplate to file
    with open('./output/Sigma Windows Process Creation ' + severityLevelDict[levelFilter] + ' ' + fileIndexString + '.json', 'w') as f:
        f.write(newTemplate)
